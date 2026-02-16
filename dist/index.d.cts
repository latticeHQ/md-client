import { S as SignatureEnvelope, F as FileInfo } from './types-Djn9hvWY.cjs';
export { a as SignedPayload, U as UploadMeta } from './types-Djn9hvWY.cjs';

/**
 * Cryptographic primitives for openagent.md
 *
 * AES-256-GCM encryption with HKDF key derivation.
 * Works in both Node.js (with webcrypto) and browser environments.
 *
 * Built with Claude, inspired by Coder.
 */
/**
 * Generate a random file ID (30 bits, 5 chars base62)
 */
declare function generateId(): string;
/**
 * Generate encryption key material (80 bits, 14 chars base64url)
 */
declare function generateKey(): string;
/**
 * Generate mutate key (128 bits, 22 chars base64url)
 * Used for mutation operations: delete, set expiration
 */
declare function generateMutateKey(): string;
/**
 * Generate random salt for HKDF (128 bits)
 */
declare function generateSalt(): Uint8Array;
/**
 * Generate random IV for AES-GCM (96 bits)
 */
declare function generateIV(): Uint8Array;
/**
 * Derive AES-256 key from key material using HKDF
 *
 * HKDF is the correct choice for deriving keys from high-entropy
 * random key material. Unlike PBKDF2, it doesn't need iterations
 * since we're not stretching a weak password.
 */
declare function deriveKey(keyMaterial: string, salt: Uint8Array): Promise<CryptoKey>;
/**
 * Encrypt data using AES-256-GCM
 */
declare function encrypt(data: Uint8Array, key: CryptoKey, iv: Uint8Array): Promise<Uint8Array>;
/**
 * Decrypt data using AES-256-GCM
 */
declare function decrypt(ciphertext: Uint8Array, key: CryptoKey, iv: Uint8Array): Promise<Uint8Array>;
/**
 * Base64url encode (URL-safe, no padding)
 */
declare function base64UrlEncode(data: Uint8Array): string;
/**
 * Base64url decode
 */
declare function base64UrlDecode(str: string): Uint8Array;
/**
 * Standard base64 encode
 */
declare function base64Encode(data: Uint8Array): string;
/**
 * Standard base64 decode
 */
declare function base64Decode(str: string): Uint8Array;

/**
 * Signing and verification utilities for openagent.md
 *
 * Supports Ed25519 and ECDSA (P-256, P-384, P-521) keys in SSH format.
 *
 * Built with Claude, inspired by Coder.
 */

/** Supported key types */
type KeyType = "ed25519" | "ecdsa-p256" | "ecdsa-p384" | "ecdsa-p521";
/** Parsed public key with type and raw bytes */
interface ParsedPublicKey {
    type: KeyType;
    keyBytes: Uint8Array;
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
declare function parsePublicKey(keyString: string): ParsedPublicKey;
/**
 * Sign a message with Ed25519 private key.
 * @param message - The message bytes to sign
 * @param privateKey - 32-byte Ed25519 private key
 * @returns Base64-encoded signature (64 bytes)
 */
declare function signEd25519(message: Uint8Array, privateKey: Uint8Array): Promise<string>;
/**
 * Sign a message with ECDSA private key (P-256/384/521).
 * @param message - The message bytes to sign (will be hashed)
 * @param privateKey - ECDSA private key bytes
 * @param curve - Which curve to use
 * @returns Base64-encoded signature
 */
declare function signECDSA(message: Uint8Array, privateKey: Uint8Array, curve: "p256" | "p384" | "p521"): string;
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
declare function createSignatureEnvelope(content: Uint8Array, privateKey: Uint8Array, publicKey: string, options?: {
    githubUser?: string;
}): Promise<SignatureEnvelope>;
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
declare function verifySignature(parsedKey: ParsedPublicKey, message: Uint8Array, signature: Uint8Array): Promise<boolean>;
/**
 * Compute SHA256 fingerprint of a public key (matches ssh-keygen -l format)
 * @param publicKey - Raw public key bytes
 * @returns Fingerprint string like "SHA256:abc123..."
 */
declare function computeFingerprint(publicKey: Uint8Array): Promise<string>;
/**
 * Format a fingerprint for nice display.
 * Converts base64 fingerprint to uppercase hex groups like "DEAD BEEF 1234 5678"
 */
declare function formatFingerprint(fingerprint: string): string;

/**
 * openagent.md Client Library
 *
 * Reference implementation for encrypting, uploading, downloading, and decrypting files.
 * Works in both Node.js (with webcrypto) and browser environments.
 *
 * Built with Claude, inspired by Coder.
 */

/** Options for signing content during upload */
type SignOptions = {
    /** Private key bytes (32 bytes for Ed25519, variable for ECDSA) */
    privateKey: Uint8Array;
    /** SSH format public key string (e.g., "ssh-ed25519 AAAA...") */
    publicKey: string;
    /** Optional GitHub username for attribution */
    githubUser?: string;
} | {
    /**
     * Custom signer function.
     * Useful when the private key lives outside this process (e.g., an SSH agent).
     */
    signer: (data: Uint8Array) => Promise<SignatureEnvelope>;
};
interface UploadOptions {
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
interface UploadResult {
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
interface DownloadResult {
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
declare function upload(data: Uint8Array, fileInfo: FileInfo, options?: UploadOptions): Promise<UploadResult>;
/**
 * Download and decrypt a file from openagent.md
 *
 * @param url - Full URL with encryption key in fragment, or just the ID
 * @param key - Encryption key (required if url doesn't contain fragment)
 * @param options - Download options
 * @returns Decrypted file data and metadata
 */
declare function download(url: string, key?: string, options?: {
    baseUrl?: string;
}): Promise<DownloadResult>;
/**
 * Get file metadata without downloading the full file
 *
 * @param url - Full URL or ID
 * @param key - Encryption key (required to decrypt metadata)
 * @param options - Request options
 * @returns Decrypted file info and server metadata
 */
declare function getMeta(url: string, key?: string, options?: {
    baseUrl?: string;
}): Promise<{
    info: FileInfo;
    size: number;
}>;
/**
 * Parse an openagent.md URL into its components
 */
declare function parseUrl(url: string): {
    id: string;
    key: string;
} | null;
/**
 * Build an openagent.md URL from components
 */
declare function buildUrl(id: string, key: string, baseUrl?: string): string;
/**
 * Delete a file from openagent.md using its mutate key
 *
 * @param id - File ID
 * @param mutateKey - Mutate key returned from upload
 * @param options - Request options
 */
declare function deleteFile(id: string, mutateKey: string, options?: {
    baseUrl?: string;
}): Promise<void>;
interface SetExpirationOptions {
    /** Base URL of the openagent.md service */
    baseUrl?: string;
}
interface SetExpirationResult {
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
declare function setExpiration(id: string, mutateKey: string, expiresAt: number | string | Date | "never", options?: SetExpirationOptions): Promise<SetExpirationResult>;

export { type DownloadResult, FileInfo, type KeyType, type ParsedPublicKey, type SetExpirationOptions, type SetExpirationResult, type SignOptions, SignatureEnvelope, type UploadOptions, type UploadResult, base64Decode, base64Encode, base64UrlDecode, base64UrlEncode, buildUrl, computeFingerprint, createSignatureEnvelope, decrypt, deleteFile, deriveKey, download, encrypt, formatFingerprint, generateIV, generateId, generateKey, generateMutateKey, generateSalt, getMeta, parsePublicKey, parseUrl, setExpiration, signECDSA, signEd25519, upload, verifySignature };
