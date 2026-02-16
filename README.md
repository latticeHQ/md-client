# @latticeruntime/md-client

Client library for [openagent.md](https://openagent.md) encrypted file sharing with signature support.

Inspired by [Coder's](https://github.com/coder) approach to encrypted file sharing. Built with Claude.

## Installation

```bash
npm install @latticeruntime/md-client
# or
bun add @latticeruntime/md-client
```

## Features

- **End-to-end encryption** — AES-256-GCM with HKDF key derivation
- **Message signing** — Ed25519 and ECDSA (P-256, P-384, P-521) support
- **SSH key format** — Parse and use standard OpenSSH public keys
- **Zero-knowledge** — Server never sees plaintext content or signatures
- **Minimal dependencies** — Only `@noble/*` for cryptographic primitives

## Usage

### Upload content

```typescript
import { upload } from '@latticeruntime/md-client';

const content = new TextEncoder().encode('# Hello World');
const result = await upload(
  content,
  { name: 'message.md', type: 'text/markdown', size: content.length },
  { expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 } // 7 days
);

console.log(result.url);       // https://openagent.md/Ab3Xy#key...
console.log(result.mutateKey); // Store for deletion/expiration updates
```

### Download content

```typescript
import { download } from '@latticeruntime/md-client';

const { data, info, signature } = await download('https://openagent.md/Ab3Xy#key...');
console.log(new TextDecoder().decode(data));

if (signature) {
  console.log('Signed by:', signature.publicKey);
}
```

### Upload with signature

Signed uploads embed plaintext as JSON (`{ content: string, sig: SignatureEnvelope }`), so the
content must be valid UTF-8 text.

#### Option A: let the library create the signature

```typescript
import { upload } from '@latticeruntime/md-client';

const content = new TextEncoder().encode('# Signed Message');

const result = await upload(
  content,
  { name: 'signed.md', type: 'text/markdown', size: content.length },
  {
    sign: {
      privateKey, // Uint8Array (Ed25519: 32 bytes)
      publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...', // OpenSSH public key
      githubUser: 'username', // optional attribution
    },
  }
);
```

#### Option B: provide a precomputed SignatureEnvelope

```typescript
import { upload, createSignatureEnvelope } from '@latticeruntime/md-client';

const content = new TextEncoder().encode('# Signed Message');

const signature = await createSignatureEnvelope(
  content,
  privateKey,
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...',
  { githubUser: 'username' }
);

const result = await upload(
  content,
  { name: 'signed.md', type: 'text/markdown', size: content.length },
  { signature }
);
```

#### Option C (Node.js): sign via SSH agent (e.g., 1Password)

```typescript
import { upload } from '@latticeruntime/md-client';
import { createSshAgentSigner } from '@latticeruntime/md-client/ssh-agent';

const content = new TextEncoder().encode('# Signed Message');

const signer = await createSshAgentSigner({ githubUser: 'username' });

const result = await upload(
  content,
  { name: 'signed.md', type: 'text/markdown', size: content.length },
  { sign: { signer } }
);
```

### Verify signatures

```typescript
import { parsePublicKey, verifySignature, base64Decode } from '@latticeruntime/md-client';

const parsedKey = parsePublicKey('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...');
const sigBytes = base64Decode(signature.sig);
const messageBytes = new TextEncoder().encode(content);

const valid = await verifySignature(parsedKey, messageBytes, sigBytes);
```

### Delete or update expiration

```typescript
import { deleteFile, setExpiration } from '@latticeruntime/md-client';

// Delete file
await deleteFile(result.id, result.mutateKey);

// Update expiration
await setExpiration(result.id, result.mutateKey, Date.now() + 30 * 24 * 60 * 60 * 1000);

// Remove expiration
await setExpiration(result.id, result.mutateKey, 'never');
```

## API Reference

### Client Operations

| Function | Description |
|----------|-------------|
| `upload(data, fileInfo, options?)` | Encrypt and upload content |
| `download(url, key?, options?)` | Download and decrypt content |
| `getMeta(url, key?, options?)` | Get file metadata without downloading |
| `deleteFile(id, mutateKey, options?)` | Delete a file |
| `setExpiration(id, mutateKey, expiresAt, options?)` | Update file expiration |
| `parseUrl(url)` | Parse openagent.md URL into id + key |
| `buildUrl(id, key, baseUrl?)` | Build openagent.md URL from components |

### Signing

| Function | Description |
|----------|-------------|
| `createSignatureEnvelope(content, privateKey, publicKey, options?)` | Create a signature envelope for upload |
| `signEd25519(message, privateKey)` | Sign with Ed25519 |
| `signECDSA(message, privateKey, curve)` | Sign with ECDSA |
| `verifySignature(parsedKey, message, signature)` | Verify a signature |
| `parsePublicKey(keyString)` | Parse SSH public key |
| `computeFingerprint(publicKey)` | Compute SHA256 fingerprint |
| `formatFingerprint(fingerprint)` | Format fingerprint for display |

#### Node-only SSH agent helpers

These helpers are available from `@latticeruntime/md-client/ssh-agent` (Node.js only):

| Function | Description |
|----------|-------------|
| `createSshAgentSigner(options?)` | Create a signer callback compatible with `upload(..., { sign: { signer } })` |
| `createSshAgentSignatureEnvelope(data, options?)` | One-shot helper that returns a `SignatureEnvelope` |

### Types

```typescript
interface FileInfo {
  name: string;
  type: string;
  size: number;
  model?: string;    // AI model (e.g., "claude-sonnet-4-20250514")
  thinking?: string; // Thinking level (e.g., "medium")
}

interface SignatureEnvelope {
  sig: string;        // Base64-encoded signature
  publicKey: string;  // SSH format public key
  githubUser?: string; // Optional: claimed GitHub username for attribution
}

type KeyType = 'ed25519' | 'ecdsa-p256' | 'ecdsa-p384' | 'ecdsa-p521';
```

## Publishing

```bash
npm publish --access public
```

## License

MIT

Built with [Claude](https://claude.ai), inspired by [Coder](https://github.com/coder).
