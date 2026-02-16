/**
 * Core types for openagent.md client library.
 *
 * Built with Claude, inspired by Coder.
 */
/**
 * File info encrypted client-side (never seen by server in plaintext)
 */
interface FileInfo {
    name: string;
    type: string;
    size: number;
    model?: string;
    thinking?: string;
}
/**
 * Metadata header sent with upload (X-Lattice-Meta)
 * Also used in response header with createdAt added
 */
interface UploadMeta {
    salt: string;
    iv: string;
    encryptedMeta: string;
    createdAt?: string;
    expiresAt?: string;
}
/**
 * Signature envelope - contains all signature-related data.
 */
interface SignatureEnvelope {
    sig: string;
    publicKey: string;
    githubUser?: string;
}
/**
 * Signed content payload (decrypted).
 * When a signature is present, the decrypted blob is JSON with this structure.
 * Legacy (unsigned) content decrypts directly to the raw content bytes.
 */
interface SignedPayload {
    content: string;
    sig: SignatureEnvelope;
}

export type { FileInfo as F, SignatureEnvelope as S, UploadMeta as U, SignedPayload as a };
