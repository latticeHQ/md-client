import { S as SignatureEnvelope } from './types-Djn9hvWY.cjs';

/**
 * SSH-agent signer for @latticeruntime/md-client.
 *
 * This module is Node.js-only. It signs bytes via SSH_AUTH_SOCK (e.g. 1Password's SSH agent)
 * and returns an openagent.md-compatible SignatureEnvelope.
 *
 * Built with Claude, inspired by Coder.
 */

interface CreateSshAgentSignerOptions {
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
declare function createSshAgentSigner(options?: CreateSshAgentSignerOptions): Promise<(data: Uint8Array) => Promise<SignatureEnvelope>>;
/**
 * Convenience helper for signing a single payload using the SSH agent.
 */
declare function createSshAgentSignatureEnvelope(data: Uint8Array, options?: CreateSshAgentSignerOptions): Promise<SignatureEnvelope>;

export { type CreateSshAgentSignerOptions, createSshAgentSignatureEnvelope, createSshAgentSigner };
