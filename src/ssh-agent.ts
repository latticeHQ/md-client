/**
 * SSH-agent signer for @latticeruntime/md-client.
 *
 * This module is Node.js-only. It signs bytes via SSH_AUTH_SOCK (e.g. 1Password's SSH agent)
 * and returns an openagent.md-compatible SignatureEnvelope.
 *
 * Built with Claude, inspired by Coder.
 */

import { Buffer } from "buffer";
import * as net from "net";

import { computeFingerprint, parsePublicKey } from "./signing";
import type { SignatureEnvelope } from "./types";

// SSH agent protocol constants
const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENT_IDENTITIES_ANSWER = 12;
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;

const SUPPORTED_KEY_TYPES = new Set([
  "ssh-ed25519",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
]);

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function readUint32BE(data: Uint8Array, offset: number): number {
  assert(offset + 4 <= data.length, "Invalid uint32");
  return new DataView(data.buffer as ArrayBuffer, data.byteOffset + offset, 4).getUint32(0);
}

function readSshString(data: Uint8Array, offset: number): { value: Uint8Array; nextOffset: number } {
  const len = readUint32BE(data, offset);
  const start = offset + 4;
  const end = start + len;
  assert(end <= data.length, "Invalid SSH string length");
  return { value: data.slice(start, end), nextOffset: end };
}

function writeUint32BE(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer as ArrayBuffer).setUint32(0, value);
  return out;
}

function writeSshString(value: Uint8Array): Uint8Array {
  const lenBytes = writeUint32BE(value.length);
  const out = new Uint8Array(4 + value.length);
  out.set(lenBytes, 0);
  out.set(value, 4);
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function leftPad(bytes: Uint8Array, length: number): Uint8Array {
  assert(bytes.length <= length, "Value is longer than expected");
  if (bytes.length === length) return bytes;
  const out = new Uint8Array(length);
  out.set(bytes, length - bytes.length);
  return out;
}

function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) {
    start++;
  }
  return bytes.slice(start);
}

interface AgentIdentity {
  type: string;
  keyBlob: Uint8Array;
  publicKey: string;
  fingerprint: string;
}

class SocketReader {
  private buffered = new Uint8Array(0);
  private pending?: {
    size: number;
    resolve: (data: Uint8Array) => void;
    reject: (err: Error) => void;
  };

  constructor(private socket: net.Socket) {
    socket.on("data", (chunk: Buffer) => {
      const bytes = new Uint8Array(chunk);
      // @ts-expect-error - Uint8Array<ArrayBufferLike> vs Uint8Array<ArrayBuffer> in TS 5.9+
      this.buffered = concatBytes(this.buffered, bytes);

      if (this.pending && this.buffered.length >= this.pending.size) {
        const { size, resolve } = this.pending;
        this.pending = undefined;
        const out = this.buffered.slice(0, size);
        this.buffered = this.buffered.slice(size);
        resolve(out);
      }
    });

    socket.on("error", (err: Error) => {
      if (this.pending) {
        const { reject } = this.pending;
        this.pending = undefined;
        reject(err);
      }
    });

    socket.on("end", () => {
      if (this.pending) {
        const { reject } = this.pending;
        this.pending = undefined;
        reject(new Error("SSH agent socket ended unexpectedly"));
      }
    });
  }

  async read(size: number): Promise<Uint8Array> {
    assert(!this.pending, "Concurrent reads are not supported");

    if (this.buffered.length >= size) {
      const out = this.buffered.slice(0, size);
      this.buffered = this.buffered.slice(size);
      return out;
    }

    return await new Promise((resolve, reject) => {
      this.pending = { size, resolve, reject };
    });
  }
}

async function connectToAgent(socketPath: string): Promise<net.Socket> {
  return await new Promise((resolve, reject) => {
    const socket = net.connect(socketPath);
    socket.once("connect", () => resolve(socket));
    socket.once("error", reject);
  });
}

async function agentRequest(socketPath: string, requestType: number, payload: Uint8Array): Promise<Uint8Array> {
  const socket = await connectToAgent(socketPath);
  const reader = new SocketReader(socket);

  try {
    const message = concatBytes(
      writeUint32BE(1 + payload.length),
      new Uint8Array([requestType]),
      payload,
    );
    socket.write(message);

    const lenBytes = await reader.read(4);
    const responseLen = readUint32BE(lenBytes, 0);
    const response = await reader.read(responseLen);
    return response;
  } finally {
    socket.end();
  }
}

async function listAgentIdentities(socketPath: string): Promise<AgentIdentity[]> {
  const response = await agentRequest(socketPath, SSH_AGENTC_REQUEST_IDENTITIES, new Uint8Array(0));

  assert(response[0] === SSH_AGENT_IDENTITIES_ANSWER, `Unexpected SSH agent response type: ${response[0]}`);

  let offset = 1;
  const nkeys = readUint32BE(response, offset);
  offset += 4;

  const identities: AgentIdentity[] = [];

  for (let i = 0; i < nkeys; i++) {
    const keyResult = readSshString(response, offset);
    const keyBlob = keyResult.value;
    offset = keyResult.nextOffset;

    const commentResult = readSshString(response, offset);
    offset = commentResult.nextOffset;

    const { value: typeBytes } = readSshString(keyBlob, 0);
    const type = new TextDecoder().decode(typeBytes);

    if (!SUPPORTED_KEY_TYPES.has(type)) {
      continue;
    }

    const publicKey = `${type} ${Buffer.from(keyBlob).toString("base64")}`;
    const parsed = parsePublicKey(publicKey);
    const fingerprint = await computeFingerprint(parsed.keyBytes);
    identities.push({ type, keyBlob, publicKey, fingerprint });
  }

  return identities;
}

function parseOpenSshPublicKey(key: string): { type: string; keyBlob: Uint8Array } {
  const trimmed = key.trim();
  const parts = trimmed.split(" ");
  assert(parts.length >= 2, "Invalid publicKey format");
  const type = parts[0];
  const keyBlob = new Uint8Array(Buffer.from(parts[1], "base64"));
  return { type, keyBlob };
}

function selectIdentity(identities: AgentIdentity[], options: CreateSshAgentSignerOptions): AgentIdentity {
  assert(identities.length > 0, "No supported SSH keys found in SSH agent");

  if (options.publicKey) {
    const target = parseOpenSshPublicKey(options.publicKey);
    const match = identities.find(
      (id) => id.type === target.type && Buffer.compare(Buffer.from(id.keyBlob), Buffer.from(target.keyBlob)) === 0,
    );
    assert(match, "Requested publicKey not found in SSH agent");
    return match;
  }

  if (options.fingerprint) {
    const match = identities.find((id) => id.fingerprint === options.fingerprint);
    assert(match, "Requested fingerprint not found in SSH agent");
    return match;
  }

  // Prefer Ed25519 keys by default
  const ed25519 = identities.find((id) => id.type === "ssh-ed25519");
  return ed25519 ?? identities[0];
}

function decodeSshSignatureBlob(signatureBlob: Uint8Array): { algorithm: string; signature: Uint8Array } {
  const algResult = readSshString(signatureBlob, 0);
  const algorithm = new TextDecoder().decode(algResult.value);
  const sigResult = readSshString(signatureBlob, algResult.nextOffset);
  return { algorithm, signature: sigResult.value };
}

function sshSignatureToRaw(algorithm: string, signature: Uint8Array): Uint8Array {
  if (algorithm === "ssh-ed25519") {
    assert(signature.length === 64, "Invalid Ed25519 signature length");
    return signature;
  }

  const ecdsaSizes: Record<string, number> = {
    "ecdsa-sha2-nistp256": 32,
    "ecdsa-sha2-nistp384": 48,
    "ecdsa-sha2-nistp521": 66,
  };

  const size = ecdsaSizes[algorithm];
  assert(size !== undefined, `Unsupported SSH signature algorithm: ${algorithm}`);

  // Parse DER-encoded ECDSA signature (r, s integers)
  const rResult = readSshString(signature, 0);
  const sResult = readSshString(signature, rResult.nextOffset);
  assert(sResult.nextOffset === signature.length, "Unexpected extra bytes in signature");

  const r = stripLeadingZeros(rResult.value);
  const s = stripLeadingZeros(sResult.value);
  const rawR = leftPad(r, size);
  const rawS = leftPad(s, size);

  return concatBytes(rawR, rawS);
}

async function signWithAgent(socketPath: string, identity: AgentIdentity, data: Uint8Array): Promise<Uint8Array> {
  const payload = concatBytes(
    writeSshString(identity.keyBlob),
    writeSshString(data),
    writeUint32BE(0), // flags
  );

  const response = await agentRequest(socketPath, SSH_AGENTC_SIGN_REQUEST, payload);

  assert(response[0] === SSH_AGENT_SIGN_RESPONSE, `Unexpected SSH agent sign response type: ${response[0]}`);

  const sigResult = readSshString(response, 1);
  const { algorithm, signature } = decodeSshSignatureBlob(sigResult.value);

  assert(algorithm === identity.type, `SSH agent signed with ${algorithm} but identity is ${identity.type}`);

  return sshSignatureToRaw(algorithm, signature);
}

export interface CreateSshAgentSignerOptions {
  /** Override SSH agent socket (defaults to process.env.SSH_AUTH_SOCK) */
  sshAuthSock?: string;
  /** Select a specific key by OpenSSH public key string */
  publicKey?: string;
  /** Select a specific key by openagent.md fingerprint (SHA256:...) */
  fingerprint?: string;
  /** Optional GitHub username to include for attribution */
  githubUser?: string;
}

/**
 * Create a signer callback compatible with UploadOptions.sign.
 */
export async function createSshAgentSigner(
  options: CreateSshAgentSignerOptions = {},
): Promise<(data: Uint8Array) => Promise<SignatureEnvelope>> {
  const socketPath = options.sshAuthSock ?? process.env.SSH_AUTH_SOCK;
  assert(socketPath, "SSH_AUTH_SOCK is not set");

  const identities = await listAgentIdentities(socketPath);
  const selected = selectIdentity(identities, options);

  return async (data: Uint8Array): Promise<SignatureEnvelope> => {
    const signatureBytes = await signWithAgent(socketPath, selected, data);
    return {
      sig: Buffer.from(signatureBytes).toString("base64"),
      publicKey: selected.publicKey,
      ...(options.githubUser && { githubUser: options.githubUser }),
    };
  };
}

/**
 * Convenience helper for signing a single payload using the SSH agent.
 */
export async function createSshAgentSignatureEnvelope(
  data: Uint8Array,
  options: CreateSshAgentSignerOptions = {},
): Promise<SignatureEnvelope> {
  const signer = await createSshAgentSigner(options);
  return await signer(data);
}
