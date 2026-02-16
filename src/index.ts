/**
 * @latticeruntime/md-client
 *
 * Client library for openagent.md encrypted file sharing with signature support.
 *
 * Built with Claude, inspired by Coder.
 */

// Types
export type { FileInfo, SignatureEnvelope, SignedPayload, UploadMeta } from "./types";

// Crypto utilities
export {
  generateId,
  generateKey,
  generateMutateKey,
  generateSalt,
  generateIV,
  deriveKey,
  encrypt,
  decrypt,
  base64UrlEncode,
  base64UrlDecode,
  base64Encode,
  base64Decode,
} from "./crypto";

// Signing & verification
export type { KeyType, ParsedPublicKey } from "./signing";
export {
  parsePublicKey,
  signEd25519,
  signECDSA,
  createSignatureEnvelope,
  verifySignature,
  computeFingerprint,
  formatFingerprint,
} from "./signing";

// Client operations
export type {
  SignOptions,
  UploadOptions,
  UploadResult,
  DownloadResult,
  SetExpirationOptions,
  SetExpirationResult,
} from "./client";
export { upload, download, getMeta, parseUrl, buildUrl, deleteFile, setExpiration } from "./client";
