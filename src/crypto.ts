/**
 * Cryptographic primitives for openagent.md
 *
 * AES-256-GCM encryption with HKDF key derivation.
 * Works in both Node.js (with webcrypto) and browser environments.
 *
 * Built with Claude, inspired by Coder.
 */

const SALT_BYTES = 16;
const IV_BYTES = 12;
const KEY_BYTES = 10;
const ID_BYTES = 4;
const MUTATE_KEY_BYTES = 16;
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/**
 * Generate a random file ID (30 bits, 5 chars base62)
 */
export function generateId(): string {
  const bytes = new Uint8Array(ID_BYTES);
  crypto.getRandomValues(bytes);
  const num = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  let result = "";
  let n = num >>> 0;
  for (let i = 0; i < 5; i++) {
    result = BASE62[n % 62] + result;
    n = Math.floor(n / 62);
  }
  return result;
}

/**
 * Generate encryption key material (80 bits, 14 chars base64url)
 */
export function generateKey(): string {
  const bytes = new Uint8Array(KEY_BYTES);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/**
 * Generate mutate key (128 bits, 22 chars base64url)
 * Used for mutation operations: delete, set expiration
 */
export function generateMutateKey(): string {
  const bytes = new Uint8Array(MUTATE_KEY_BYTES);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/**
 * Generate random salt for HKDF (128 bits)
 */
export function generateSalt(): Uint8Array {
  const salt = new Uint8Array(SALT_BYTES);
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * Generate random IV for AES-GCM (96 bits)
 */
export function generateIV(): Uint8Array {
  const iv = new Uint8Array(IV_BYTES);
  crypto.getRandomValues(iv);
  return iv;
}

/**
 * Derive AES-256 key from key material using HKDF
 *
 * HKDF is the correct choice for deriving keys from high-entropy
 * random key material. Unlike PBKDF2, it doesn't need iterations
 * since we're not stretching a weak password.
 */
export async function deriveKey(keyMaterial: string, salt: Uint8Array): Promise<CryptoKey> {
  const rawKey = base64UrlDecode(keyMaterial);
  const baseKey = await crypto.subtle.importKey(
    "raw",
    rawKey.buffer as ArrayBuffer,
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt: salt.buffer as ArrayBuffer,
      info: new Uint8Array(0), // No additional context needed
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypt data using AES-256-GCM
 */
export async function encrypt(data: Uint8Array, key: CryptoKey, iv: Uint8Array): Promise<Uint8Array> {
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    key,
    data.buffer as ArrayBuffer,
  );
  return new Uint8Array(ciphertext);
}

/**
 * Decrypt data using AES-256-GCM
 */
export async function decrypt(ciphertext: Uint8Array, key: CryptoKey, iv: Uint8Array): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    key,
    ciphertext.buffer as ArrayBuffer,
  );
  return new Uint8Array(plaintext);
}

/**
 * Base64url encode (URL-safe, no padding)
 */
export function base64UrlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Base64url decode
 */
export function base64UrlDecode(str: string): Uint8Array {
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
 * Standard base64 encode
 */
export function base64Encode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data));
}

/**
 * Standard base64 decode
 */
export function base64Decode(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
