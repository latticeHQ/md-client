'use strict';

var buffer = require('buffer');
var net = require('net');
require('@noble/curves/nist.js');
var ed = require('@noble/ed25519');
var sha2_js = require('@noble/hashes/sha2.js');

function _interopNamespace(e) {
  if (e && e.__esModule) return e;
  var n = Object.create(null);
  if (e) {
    Object.keys(e).forEach(function (k) {
      if (k !== 'default') {
        var d = Object.getOwnPropertyDescriptor(e, k);
        Object.defineProperty(n, k, d.get ? d : {
          enumerable: true,
          get: function () { return e[k]; }
        });
      }
    });
  }
  n.default = e;
  return Object.freeze(n);
}

var net__namespace = /*#__PURE__*/_interopNamespace(net);
var ed__namespace = /*#__PURE__*/_interopNamespace(ed);

// src/ssh-agent.ts
ed__namespace.etc.sha512Sync = (...m) => sha2_js.sha512(ed__namespace.etc.concatBytes(...m));
var SSH_KEY_TYPES = {
  "ssh-ed25519": "ed25519",
  "ecdsa-sha2-nistp256": "ecdsa-p256",
  "ecdsa-sha2-nistp384": "ecdsa-p384",
  "ecdsa-sha2-nistp521": "ecdsa-p521"
};
function readSSHString(data, offset) {
  const view = new DataView(data.buffer, data.byteOffset);
  const len = view.getUint32(offset);
  const value = data.slice(offset + 4, offset + 4 + len);
  return { value, nextOffset: offset + 4 + len };
}
function base64DecodeInternal(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
function parsePublicKey(keyString) {
  const trimmed = keyString.trim();
  for (const [sshType, keyType] of Object.entries(SSH_KEY_TYPES)) {
    if (trimmed.startsWith(`${sshType} `)) {
      const parts = trimmed.split(" ");
      if (parts.length < 2) {
        throw new Error("Invalid SSH key format");
      }
      const keyData = base64DecodeInternal(parts[1]);
      const { value: typeBytes, nextOffset: afterType } = readSSHString(keyData, 0);
      const typeStr = new TextDecoder().decode(typeBytes);
      if (typeStr !== sshType) {
        throw new Error(`Key type mismatch: expected ${sshType}, got ${typeStr}`);
      }
      if (keyType === "ed25519") {
        const { value: rawKey } = readSSHString(keyData, afterType);
        if (rawKey.length !== 32) {
          throw new Error("Invalid Ed25519 key length");
        }
        return { type: "ed25519", keyBytes: rawKey };
      }
      const { nextOffset: afterCurve } = readSSHString(keyData, afterType);
      const { value: point } = readSSHString(keyData, afterCurve);
      return { type: keyType, keyBytes: point };
    }
  }
  const decoded = base64DecodeInternal(trimmed);
  if (decoded.length === 32) {
    return { type: "ed25519", keyBytes: decoded };
  }
  throw new Error("Unsupported public key format");
}
async function computeFingerprint(publicKey) {
  const hash = await crypto.subtle.digest("SHA-256", publicKey.buffer);
  const hashArray = new Uint8Array(hash);
  const base64 = btoa(String.fromCharCode(...hashArray));
  return `SHA256:${base64.replace(/=+$/, "")}`;
}

// src/ssh-agent.ts
var SSH_AGENTC_REQUEST_IDENTITIES = 11;
var SSH_AGENT_IDENTITIES_ANSWER = 12;
var SSH_AGENTC_SIGN_REQUEST = 13;
var SSH_AGENT_SIGN_RESPONSE = 14;
var SUPPORTED_KEY_TYPES = /* @__PURE__ */ new Set([
  "ssh-ed25519",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521"
]);
function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}
function readUint32BE(data, offset) {
  assert(offset + 4 <= data.length, "Invalid uint32");
  return new DataView(data.buffer, data.byteOffset + offset, 4).getUint32(0);
}
function readSshString(data, offset) {
  const len = readUint32BE(data, offset);
  const start = offset + 4;
  const end = start + len;
  assert(end <= data.length, "Invalid SSH string length");
  return { value: data.slice(start, end), nextOffset: end };
}
function writeUint32BE(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}
function writeSshString(value) {
  const lenBytes = writeUint32BE(value.length);
  const out = new Uint8Array(4 + value.length);
  out.set(lenBytes, 0);
  out.set(value, 4);
  return out;
}
function concatBytes(...parts) {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
function leftPad(bytes, length) {
  assert(bytes.length <= length, "Value is longer than expected");
  if (bytes.length === length) return bytes;
  const out = new Uint8Array(length);
  out.set(bytes, length - bytes.length);
  return out;
}
function stripLeadingZeros(bytes) {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) {
    start++;
  }
  return bytes.slice(start);
}
var SocketReader = class {
  constructor(socket) {
    this.socket = socket;
    socket.on("data", (chunk) => {
      const bytes = new Uint8Array(chunk);
      this.buffered = concatBytes(this.buffered, bytes);
      if (this.pending && this.buffered.length >= this.pending.size) {
        const { size, resolve } = this.pending;
        this.pending = void 0;
        const out = this.buffered.slice(0, size);
        this.buffered = this.buffered.slice(size);
        resolve(out);
      }
    });
    socket.on("error", (err) => {
      if (this.pending) {
        const { reject } = this.pending;
        this.pending = void 0;
        reject(err);
      }
    });
    socket.on("end", () => {
      if (this.pending) {
        const { reject } = this.pending;
        this.pending = void 0;
        reject(new Error("SSH agent socket ended unexpectedly"));
      }
    });
  }
  buffered = new Uint8Array(0);
  pending;
  async read(size) {
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
};
async function connectToAgent(socketPath) {
  return await new Promise((resolve, reject) => {
    const socket = net__namespace.connect(socketPath);
    socket.once("connect", () => resolve(socket));
    socket.once("error", reject);
  });
}
async function agentRequest(socketPath, requestType, payload) {
  const socket = await connectToAgent(socketPath);
  const reader = new SocketReader(socket);
  try {
    const message = concatBytes(
      writeUint32BE(1 + payload.length),
      new Uint8Array([requestType]),
      payload
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
async function listAgentIdentities(socketPath) {
  const response = await agentRequest(socketPath, SSH_AGENTC_REQUEST_IDENTITIES, new Uint8Array(0));
  assert(response[0] === SSH_AGENT_IDENTITIES_ANSWER, `Unexpected SSH agent response type: ${response[0]}`);
  let offset = 1;
  const nkeys = readUint32BE(response, offset);
  offset += 4;
  const identities = [];
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
    const publicKey = `${type} ${buffer.Buffer.from(keyBlob).toString("base64")}`;
    const parsed = parsePublicKey(publicKey);
    const fingerprint = await computeFingerprint(parsed.keyBytes);
    identities.push({ type, keyBlob, publicKey, fingerprint });
  }
  return identities;
}
function parseOpenSshPublicKey(key) {
  const trimmed = key.trim();
  const parts = trimmed.split(" ");
  assert(parts.length >= 2, "Invalid publicKey format");
  const type = parts[0];
  const keyBlob = new Uint8Array(buffer.Buffer.from(parts[1], "base64"));
  return { type, keyBlob };
}
function selectIdentity(identities, options) {
  assert(identities.length > 0, "No supported SSH keys found in SSH agent");
  if (options.publicKey) {
    const target = parseOpenSshPublicKey(options.publicKey);
    const match = identities.find(
      (id) => id.type === target.type && buffer.Buffer.compare(buffer.Buffer.from(id.keyBlob), buffer.Buffer.from(target.keyBlob)) === 0
    );
    assert(match, "Requested publicKey not found in SSH agent");
    return match;
  }
  if (options.fingerprint) {
    const match = identities.find((id) => id.fingerprint === options.fingerprint);
    assert(match, "Requested fingerprint not found in SSH agent");
    return match;
  }
  const ed25519 = identities.find((id) => id.type === "ssh-ed25519");
  return ed25519 ?? identities[0];
}
function decodeSshSignatureBlob(signatureBlob) {
  const algResult = readSshString(signatureBlob, 0);
  const algorithm = new TextDecoder().decode(algResult.value);
  const sigResult = readSshString(signatureBlob, algResult.nextOffset);
  return { algorithm, signature: sigResult.value };
}
function sshSignatureToRaw(algorithm, signature) {
  if (algorithm === "ssh-ed25519") {
    assert(signature.length === 64, "Invalid Ed25519 signature length");
    return signature;
  }
  const ecdsaSizes = {
    "ecdsa-sha2-nistp256": 32,
    "ecdsa-sha2-nistp384": 48,
    "ecdsa-sha2-nistp521": 66
  };
  const size = ecdsaSizes[algorithm];
  assert(size !== void 0, `Unsupported SSH signature algorithm: ${algorithm}`);
  const rResult = readSshString(signature, 0);
  const sResult = readSshString(signature, rResult.nextOffset);
  assert(sResult.nextOffset === signature.length, "Unexpected extra bytes in signature");
  const r = stripLeadingZeros(rResult.value);
  const s = stripLeadingZeros(sResult.value);
  const rawR = leftPad(r, size);
  const rawS = leftPad(s, size);
  return concatBytes(rawR, rawS);
}
async function signWithAgent(socketPath, identity, data) {
  const payload = concatBytes(
    writeSshString(identity.keyBlob),
    writeSshString(data),
    writeUint32BE(0)
    // flags
  );
  const response = await agentRequest(socketPath, SSH_AGENTC_SIGN_REQUEST, payload);
  assert(response[0] === SSH_AGENT_SIGN_RESPONSE, `Unexpected SSH agent sign response type: ${response[0]}`);
  const sigResult = readSshString(response, 1);
  const { algorithm, signature } = decodeSshSignatureBlob(sigResult.value);
  assert(algorithm === identity.type, `SSH agent signed with ${algorithm} but identity is ${identity.type}`);
  return sshSignatureToRaw(algorithm, signature);
}
async function createSshAgentSigner(options = {}) {
  const socketPath = options.sshAuthSock ?? process.env.SSH_AUTH_SOCK;
  assert(socketPath, "SSH_AUTH_SOCK is not set");
  const identities = await listAgentIdentities(socketPath);
  const selected = selectIdentity(identities, options);
  return async (data) => {
    const signatureBytes = await signWithAgent(socketPath, selected, data);
    return {
      sig: buffer.Buffer.from(signatureBytes).toString("base64"),
      publicKey: selected.publicKey,
      ...options.githubUser && { githubUser: options.githubUser }
    };
  };
}
async function createSshAgentSignatureEnvelope(data, options = {}) {
  const signer = await createSshAgentSigner(options);
  return await signer(data);
}

exports.createSshAgentSignatureEnvelope = createSshAgentSignatureEnvelope;
exports.createSshAgentSigner = createSshAgentSigner;
//# sourceMappingURL=ssh-agent.cjs.map
//# sourceMappingURL=ssh-agent.cjs.map