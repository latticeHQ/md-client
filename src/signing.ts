/**
 * Signing and verification utilities for openagent.md
 *
 * Supports Ed25519 and ECDSA (P-256, P-384, P-521) keys in SSH format.
 *
 * Built with Claude, inspired by Coder.
 */

import { p256, p384, p521 } from "@noble/curves/nist.js";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

import type { SignatureEnvelope } from "./types";

// Configure ed25519 with synchronous SHA-512
// @ts-expect-error - sha512Sync exists at runtime but not in type defs
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

/** Supported key types */
export type KeyType = "ed25519" | "ecdsa-p256" | "ecdsa-p384" | "ecdsa-p521";

/** Parsed public key with type and raw bytes */
export interface ParsedPublicKey {
  type: KeyType;
  keyBytes: Uint8Array;
}

const SSH_KEY_TYPES: Record<string, KeyType> = {
  "ssh-ed25519": "ed25519",
  "ecdsa-sha2-nistp256": "ecdsa-p256",
  "ecdsa-sha2-nistp384": "ecdsa-p384",
  "ecdsa-sha2-nistp521": "ecdsa-p521",
};

function readSSHString(data: Uint8Array, offset: number): { value: Uint8Array; nextOffset: number } {
  const view = new DataView(data.buffer as ArrayBuffer, data.byteOffset);
  const len = view.getUint32(offset);
  const value = data.slice(offset + 4, offset + 4 + len);
  return { value, nextOffset: offset + 4 + len };
}

function base64DecodeInternal(str: string): Uint8Array {
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

/**
 * Parse an SSH public key and extract the key bytes and type.
 * Supports formats:
 * - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... [comment]
 * - ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY... [comment]
 * - ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQ... [comment]
 * - ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjE... [comment]
 * - Raw base64 (32 bytes when decoded = Ed25519)
 */
export function parsePublicKey(keyString: string): ParsedPublicKey {
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

      // ECDSA: skip curve name, read point
      const { nextOffset: afterCurve } = readSSHString(keyData, afterType);
      const { value: point } = readSSHString(keyData, afterCurve);
      return { type: keyType, keyBytes: point };
    }
  }

  // Fallback: try raw base64 (Ed25519)
  const decoded = base64DecodeInternal(trimmed);
  if (decoded.length === 32) {
    return { type: "ed25519", keyBytes: decoded };
  }

  throw new Error("Unsupported public key format");
}

/**
 * Sign a message with Ed25519 private key.
 * @param message - The message bytes to sign
 * @param privateKey - 32-byte Ed25519 private key
 * @returns Base64-encoded signature (64 bytes)
 */
export async function signEd25519(message: Uint8Array, privateKey: Uint8Array): Promise<string> {
  const sig = await ed.signAsync(message, privateKey);
  return btoa(String.fromCharCode(...sig));
}

/**
 * Sign a message with ECDSA private key (P-256/384/521).
 * @param message - The message bytes to sign (will be hashed)
 * @param privateKey - ECDSA private key bytes
 * @param curve - Which curve to use
 * @returns Base64-encoded signature
 */
export function signECDSA(message: Uint8Array, privateKey: Uint8Array, curve: "p256" | "p384" | "p521"): string {
  const curves = { p256, p384, p521 };
  const sigBytes = curves[curve].sign(message, privateKey, { prehash: true });
  return btoa(String.fromCharCode(...sigBytes));
}

/**
 * Helper: Create a SignatureEnvelope from content + private key.
 * This is the high-level API for signing before upload.
 *
 * @param content - The content bytes to sign
 * @param privateKey - Private key bytes (32 bytes for Ed25519, variable for ECDSA)
 * @param publicKey - SSH format public key string (e.g., "ssh-ed25519 AAAA...")
 * @param options - Optional GitHub username for attribution
 * @returns SignatureEnvelope ready for upload
 */
export async function createSignatureEnvelope(
  content: Uint8Array,
  privateKey: Uint8Array,
  publicKey: string,
  options?: { githubUser?: string },
): Promise<SignatureEnvelope> {
  const parsed = parsePublicKey(publicKey);
  let sig: string;

  if (parsed.type === "ed25519") {
    sig = await signEd25519(content, privateKey);
  } else {
    const curve = parsed.type.replace("ecdsa-", "") as "p256" | "p384" | "p521";
    sig = signECDSA(content, privateKey, curve);
  }

  return {
    sig,
    publicKey,
    githubUser: options?.githubUser,
  };
}

/**
 * Verify a signature using the appropriate algorithm based on key type.
 * For Ed25519: signature is raw 64 bytes
 * For ECDSA: signature is DER-encoded or raw r||s format
 *
 * @param parsedKey - Parsed public key (from parsePublicKey)
 * @param message - Original message bytes
 * @param signature - Signature bytes (not base64)
 * @returns true if signature is valid
 */
export async function verifySignature(
  parsedKey: ParsedPublicKey,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    switch (parsedKey.type) {
      case "ed25519":
        return await ed.verifyAsync(signature, message, parsedKey.keyBytes);
      case "ecdsa-p256":
        return p256.verify(signature, message, parsedKey.keyBytes, { prehash: true });
      case "ecdsa-p384":
        return p384.verify(signature, message, parsedKey.keyBytes, { prehash: true });
      case "ecdsa-p521":
        return p521.verify(signature, message, parsedKey.keyBytes, { prehash: true });
      default:
        return false;
    }
  } catch {
    return false;
  }
}

/**
 * Compute SHA256 fingerprint of a public key (matches ssh-keygen -l format)
 * @param publicKey - Raw public key bytes
 * @returns Fingerprint string like "SHA256:abc123..."
 */
export async function computeFingerprint(publicKey: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", publicKey.buffer as ArrayBuffer);
  const hashArray = new Uint8Array(hash);
  const base64 = btoa(String.fromCharCode(...hashArray));
  return `SHA256:${base64.replace(/=+$/, "")}`;
}

/**
 * Format a fingerprint for nice display.
 * Converts base64 fingerprint to uppercase hex groups like "DEAD BEEF 1234 5678"
 */
export function formatFingerprint(fingerprint: string): string {
  const base64Part = fingerprint.startsWith("SHA256:") ? fingerprint.slice(7) : fingerprint;
  try {
    const binary = atob(base64Part);
    const hex = Array.from(binary)
      .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
    const short = hex.slice(0, 16);
    return short.match(/.{4}/g)?.join(" ") || short;
  } catch {
    return fingerprint.slice(0, 16).toUpperCase();
  }
}
