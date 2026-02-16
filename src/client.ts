/**
 * openagent.md Client Library
 *
 * Reference implementation for encrypting, uploading, downloading, and decrypting files.
 * Works in both Node.js (with webcrypto) and browser environments.
 *
 * Built with Claude, inspired by Coder.
 */

import {
  base64Decode,
  base64Encode,
  decrypt,
  deriveKey,
  encrypt,
  generateIV,
  generateKey,
  generateSalt,
} from "./crypto";
import { createSignatureEnvelope } from "./signing";
import type { FileInfo, SignatureEnvelope, SignedPayload } from "./types";

const DEFAULT_BASE_URL = "https://openagent.md";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function decodeUtf8Strict(data: Uint8Array): string {
  try {
    const decoded = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(data);
    const reencoded = new TextEncoder().encode(decoded);
    assert(bytesEqual(data, reencoded), "Signed uploads require UTF-8 text content");
    return decoded;
  } catch (error) {
    if (error instanceof Error && error.message === "Signed uploads require UTF-8 text content") {
      throw error;
    }
    throw new Error("Signed uploads require UTF-8 text content");
  }
}

function assertSignatureEnvelope(value: unknown): asserts value is SignatureEnvelope {
  if (!value || typeof value !== "object") {
    throw new Error("Invalid SignatureEnvelope");
  }
  const env = value as SignatureEnvelope;
  if (typeof env.sig !== "string" || env.sig.length === 0) {
    throw new Error("Invalid SignatureEnvelope.sig");
  }
  if (typeof env.publicKey !== "string" || env.publicKey.length === 0) {
    throw new Error("Invalid SignatureEnvelope.publicKey");
  }
  if (env.githubUser !== undefined && typeof env.githubUser !== "string") {
    throw new Error("Invalid SignatureEnvelope.githubUser");
  }
}

/** Options for signing content during upload */
export type SignOptions =
  | {
      /** Private key bytes (32 bytes for Ed25519, variable for ECDSA) */
      privateKey: Uint8Array;
      /** SSH format public key string (e.g., "ssh-ed25519 AAAA...") */
      publicKey: string;
      /** Optional GitHub username for attribution */
      githubUser?: string;
    }
  | {
      /**
       * Custom signer function.
       * Useful when the private key lives outside this process (e.g., an SSH agent).
       */
      signer: (data: Uint8Array) => Promise<SignatureEnvelope>;
    };

export interface UploadOptions {
  /** Base URL of the openagent.md service */
  baseUrl?: string;
  /** Expiration time (unix timestamp ms, ISO date string, or Date object) */
  expiresAt?: number | string | Date;
  /**
   * Precomputed signature envelope to embed in the encrypted payload.
   * Takes precedence over `sign`.
   */
  signature?: SignatureEnvelope;
  /**
   * Sign the content.
   *
   * When provided, the decrypted blob becomes JSON (SignedPayload) containing both
   * the content string and the signature envelope.
   */
  sign?: SignOptions;
}

export interface UploadResult {
  /** Full URL with encryption key in fragment */
  url: string;
  /** File ID (without key) */
  id: string;
  /** Encryption key (base64url) */
  key: string;
  /** Mutate key (base64url) - store this to mutate (delete, change expiration) the file later */
  mutateKey: string;
  /** Expiration timestamp (ms), if set */
  expiresAt?: number;
}

export interface DownloadResult {
  /** Decrypted file content */
  data: Uint8Array;
  /** Original file info (name, type, size) */
  info: FileInfo;
  /** Decrypted signature envelope (if present) */
  signature?: SignatureEnvelope;
}

/**
 * Encrypt and upload a file to openagent.md
 *
 * @param data - File contents as Uint8Array
 * @param fileInfo - Original file metadata (name, type, size)
 * @param options - Upload options (including optional signature)
 * @returns Upload result with URL containing encryption key
 */
export async function upload(
  data: Uint8Array,
  fileInfo: FileInfo,
  options: UploadOptions = {},
): Promise<UploadResult> {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  const keyMaterial = generateKey();
  const salt = generateSalt();
  const iv = generateIV();
  const cryptoKey = await deriveKey(keyMaterial, salt);

  const wantsSignature = options.signature !== undefined || options.sign !== undefined;
  const signedContent = wantsSignature ? decodeUtf8Strict(data) : undefined;

  let signatureEnvelope: SignatureEnvelope | undefined;

  if (options.signature !== undefined) {
    assertSignatureEnvelope(options.signature);
    signatureEnvelope = options.signature;
  } else if (options.sign) {
    if ("signer" in options.sign) {
      const envelope = await options.sign.signer(data);
      assertSignatureEnvelope(envelope);
      signatureEnvelope = envelope;
    } else {
      signatureEnvelope = await createSignatureEnvelope(data, options.sign.privateKey, options.sign.publicKey, {
        githubUser: options.sign.githubUser,
      });
      assertSignatureEnvelope(signatureEnvelope);
    }
  }

  if (wantsSignature) {
    assert(signatureEnvelope !== undefined, "Signature requested but no signature envelope was produced");
  }

  let plaintext: Uint8Array;
  if (signatureEnvelope) {
    assert(signedContent !== undefined, "Signed content string missing");
    const signed: SignedPayload = {
      content: signedContent,
      sig: signatureEnvelope,
    };
    plaintext = new TextEncoder().encode(JSON.stringify(signed));
  } else {
    plaintext = data;
  }

  const payload = await encrypt(plaintext, cryptoKey, iv);

  // Encrypt file metadata separately
  const metaJson = JSON.stringify(fileInfo);
  const metaBytes = new TextEncoder().encode(metaJson);
  const metaIv = generateIV();
  const encryptedMeta = await encrypt(metaBytes, cryptoKey, metaIv);

  const uploadMeta = {
    salt: base64Encode(salt),
    iv: base64Encode(iv),
    encryptedMeta: base64Encode(new Uint8Array([...metaIv, ...encryptedMeta])),
  };

  const headers: Record<string, string> = {
    "Content-Type": "application/octet-stream",
    "X-Lattice-Meta": btoa(JSON.stringify(uploadMeta)),
  };

  if (options.expiresAt !== undefined) {
    let expiresDate: Date;
    if (options.expiresAt instanceof Date) {
      expiresDate = options.expiresAt;
    } else if (typeof options.expiresAt === "string") {
      expiresDate = new Date(options.expiresAt);
    } else {
      expiresDate = new Date(options.expiresAt);
    }
    headers["X-Lattice-Expires"] = expiresDate.toISOString();
  }

  const response = await fetch(`${baseUrl}/`, {
    method: "POST",
    headers,
    body: payload.buffer as ArrayBuffer,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Upload failed" }));
    throw new Error(error.error || "Upload failed");
  }

  const result = await response.json();
  return {
    url: `${baseUrl}/${result.id}#${keyMaterial}`,
    id: result.id,
    key: keyMaterial,
    mutateKey: result.mutateKey,
    ...(result.expiresAt && { expiresAt: result.expiresAt }),
  };
}

/**
 * Download and decrypt a file from openagent.md
 *
 * @param url - Full URL with encryption key in fragment, or just the ID
 * @param key - Encryption key (required if url doesn't contain fragment)
 * @param options - Download options
 * @returns Decrypted file data and metadata
 */
export async function download(
  url: string,
  key?: string,
  options: { baseUrl?: string } = {},
): Promise<DownloadResult> {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  let id: string;
  let keyMaterial: string;

  if (url.includes("#")) {
    const urlObj = new URL(url);
    id = urlObj.pathname.slice(1);
    keyMaterial = urlObj.hash.slice(1);
  } else if (url.includes("/")) {
    const parts = url.split("/");
    id = parts[parts.length - 1];
    if (!key) throw new Error("Key required when URL has no fragment");
    keyMaterial = key;
  } else {
    id = url;
    if (!key) throw new Error("Key required when only ID is provided");
    keyMaterial = key;
  }

  const response = await fetch(`${baseUrl}/${id}`);
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Download failed" }));
    throw new Error(error.error || "Download failed");
  }

  const metaHeader = response.headers.get("X-Lattice-Meta");
  if (!metaHeader) {
    throw new Error("Missing metadata header");
  }

  const uploadMeta = JSON.parse(atob(metaHeader));
  const encryptedData = new Uint8Array(await response.arrayBuffer());

  const salt = base64Decode(uploadMeta.salt);
  const iv = base64Decode(uploadMeta.iv);
  const cryptoKey = await deriveKey(keyMaterial, salt);

  // Decrypt file metadata
  const encryptedMetaWithIv = base64Decode(uploadMeta.encryptedMeta);
  const metaIv = encryptedMetaWithIv.slice(0, 12);
  const encryptedMetaData = encryptedMetaWithIv.slice(12);
  const metaBytes = await decrypt(encryptedMetaData, cryptoKey, metaIv);
  const info: FileInfo = JSON.parse(new TextDecoder().decode(metaBytes));

  // Decrypt file content
  const decrypted = await decrypt(encryptedData, cryptoKey, iv);

  // Check if content is a signed payload (JSON starting with '{')
  if (decrypted[0] === 123) {
    try {
      const jsonStr = new TextDecoder().decode(decrypted);
      const parsed = JSON.parse(jsonStr) as SignedPayload;
      if (typeof parsed.content === "string" && parsed.sig) {
        const data = new TextEncoder().encode(parsed.content);
        const signature = parsed.sig;
        return { data, info, signature };
      }
    } catch {
      // Not valid JSON, treat as raw content
    }
  }

  return { data: decrypted, info };
}

/**
 * Get file metadata without downloading the full file
 *
 * @param url - Full URL or ID
 * @param key - Encryption key (required to decrypt metadata)
 * @param options - Request options
 * @returns Decrypted file info and server metadata
 */
export async function getMeta(
  url: string,
  key?: string,
  options: { baseUrl?: string } = {},
): Promise<{ info: FileInfo; size: number }> {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  let id: string;
  let keyMaterial: string;

  if (url.includes("#")) {
    const urlObj = new URL(url);
    id = urlObj.pathname.slice(1);
    keyMaterial = urlObj.hash.slice(1);
  } else if (url.includes("/")) {
    const parts = url.split("/");
    id = parts[parts.length - 1];
    if (!key) throw new Error("Key required when URL has no fragment");
    keyMaterial = key;
  } else {
    id = url;
    if (!key) throw new Error("Key required when only ID is provided");
    keyMaterial = key;
  }

  const response = await fetch(`${baseUrl}/${id}/meta`);
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Request failed" }));
    throw new Error(error.error || "Request failed");
  }

  const meta = await response.json();
  const salt = base64Decode(meta.salt);
  const cryptoKey = await deriveKey(keyMaterial, salt);

  const encryptedMetaWithIv = base64Decode(meta.encryptedMeta);
  const metaIv = encryptedMetaWithIv.slice(0, 12);
  const encryptedMetaData = encryptedMetaWithIv.slice(12);
  const metaBytes = await decrypt(encryptedMetaData, cryptoKey, metaIv);
  const info: FileInfo = JSON.parse(new TextDecoder().decode(metaBytes));

  return { info, size: meta.size };
}

/**
 * Parse an openagent.md URL into its components
 */
export function parseUrl(url: string): { id: string; key: string } | null {
  try {
    const urlObj = new URL(url);
    if (!urlObj.hash) return null;
    const id = urlObj.pathname.slice(1);
    const key = urlObj.hash.slice(1);
    if (!id || !key) return null;
    return { id, key };
  } catch {
    return null;
  }
}

/**
 * Build an openagent.md URL from components
 */
export function buildUrl(id: string, key: string, baseUrl: string = DEFAULT_BASE_URL): string {
  return `${baseUrl}/${id}#${key}`;
}

/**
 * Delete a file from openagent.md using its mutate key
 *
 * @param id - File ID
 * @param mutateKey - Mutate key returned from upload
 * @param options - Request options
 */
export async function deleteFile(
  id: string,
  mutateKey: string,
  options: { baseUrl?: string } = {},
): Promise<void> {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  const response = await fetch(`${baseUrl}/${id}`, {
    method: "DELETE",
    headers: {
      "X-Lattice-Mutate-Key": mutateKey,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Delete failed" }));
    throw new Error(error.error || "Delete failed");
  }
}

export interface SetExpirationOptions {
  /** Base URL of the openagent.md service */
  baseUrl?: string;
}

export interface SetExpirationResult {
  /** Whether the operation succeeded */
  success: boolean;
  /** File ID */
  id: string;
  /** New expiration timestamp (ms), or undefined if expiration was removed */
  expiresAt?: number;
}

/**
 * Set or remove the expiration of a file using its mutate key
 *
 * @param id - File ID
 * @param mutateKey - Mutate key returned from upload
 * @param expiresAt - New expiration time (unix timestamp ms, ISO date string, Date object, or "never" to remove expiration)
 * @param options - Request options
 * @returns Result with new expiration info
 */
export async function setExpiration(
  id: string,
  mutateKey: string,
  expiresAt: number | string | Date | "never",
  options: SetExpirationOptions = {},
): Promise<SetExpirationResult> {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;

  let expiresHeader: string;
  if (expiresAt === "never") {
    expiresHeader = "never";
  } else if (expiresAt instanceof Date) {
    expiresHeader = expiresAt.toISOString();
  } else if (typeof expiresAt === "string") {
    expiresHeader = new Date(expiresAt).toISOString();
  } else {
    expiresHeader = new Date(expiresAt).toISOString();
  }

  const response = await fetch(`${baseUrl}/${id}`, {
    method: "PATCH",
    headers: {
      "X-Lattice-Mutate-Key": mutateKey,
      "X-Lattice-Expires": expiresHeader,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Set expiration failed" }));
    throw new Error(error.error || "Set expiration failed");
  }

  return response.json();
}
