import { p521, p384, p256 } from '@noble/curves/nist.js';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

// src/crypto.ts
var SALT_BYTES = 16;
var IV_BYTES = 12;
var KEY_BYTES = 10;
var ID_BYTES = 4;
var MUTATE_KEY_BYTES = 16;
var BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
function generateId() {
  const bytes = new Uint8Array(ID_BYTES);
  crypto.getRandomValues(bytes);
  const num = bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
  let result = "";
  let n = num >>> 0;
  for (let i = 0; i < 5; i++) {
    result = BASE62[n % 62] + result;
    n = Math.floor(n / 62);
  }
  return result;
}
function generateKey() {
  const bytes = new Uint8Array(KEY_BYTES);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}
function generateMutateKey() {
  const bytes = new Uint8Array(MUTATE_KEY_BYTES);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}
function generateSalt() {
  const salt = new Uint8Array(SALT_BYTES);
  crypto.getRandomValues(salt);
  return salt;
}
function generateIV() {
  const iv = new Uint8Array(IV_BYTES);
  crypto.getRandomValues(iv);
  return iv;
}
async function deriveKey(keyMaterial, salt) {
  const rawKey = base64UrlDecode(keyMaterial);
  const baseKey = await crypto.subtle.importKey(
    "raw",
    rawKey.buffer,
    "HKDF",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt: salt.buffer,
      info: new Uint8Array(0),
      // No additional context needed
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function encrypt(data, key, iv) {
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv.buffer },
    key,
    data.buffer
  );
  return new Uint8Array(ciphertext);
}
async function decrypt(ciphertext, key, iv) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer },
    key,
    ciphertext.buffer
  );
  return new Uint8Array(plaintext);
}
function base64UrlEncode(data) {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64UrlDecode(str) {
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
function base64Encode(data) {
  return btoa(String.fromCharCode(...data));
}
function base64Decode(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
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
async function signEd25519(message, privateKey) {
  const sig = await ed.signAsync(message, privateKey);
  return btoa(String.fromCharCode(...sig));
}
function signECDSA(message, privateKey, curve) {
  const curves = { p256, p384, p521 };
  const sigBytes = curves[curve].sign(message, privateKey, { prehash: true });
  return btoa(String.fromCharCode(...sigBytes));
}
async function createSignatureEnvelope(content, privateKey, publicKey, options) {
  const parsed = parsePublicKey(publicKey);
  let sig;
  if (parsed.type === "ed25519") {
    sig = await signEd25519(content, privateKey);
  } else {
    const curve = parsed.type.replace("ecdsa-", "");
    sig = signECDSA(content, privateKey, curve);
  }
  return {
    sig,
    publicKey,
    githubUser: options?.githubUser
  };
}
async function verifySignature(parsedKey, message, signature) {
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
async function computeFingerprint(publicKey) {
  const hash = await crypto.subtle.digest("SHA-256", publicKey.buffer);
  const hashArray = new Uint8Array(hash);
  const base64 = btoa(String.fromCharCode(...hashArray));
  return `SHA256:${base64.replace(/=+$/, "")}`;
}
function formatFingerprint(fingerprint) {
  const base64Part = fingerprint.startsWith("SHA256:") ? fingerprint.slice(7) : fingerprint;
  try {
    const binary = atob(base64Part);
    const hex = Array.from(binary).map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("").toUpperCase();
    const short = hex.slice(0, 16);
    return short.match(/.{4}/g)?.join(" ") || short;
  } catch {
    return fingerprint.slice(0, 16).toUpperCase();
  }
}

// src/client.ts
var DEFAULT_BASE_URL = "https://openagent.md";
function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}
function bytesEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
function decodeUtf8Strict(data) {
  try {
    const decoded = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true
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
function assertSignatureEnvelope(value) {
  if (!value || typeof value !== "object") {
    throw new Error("Invalid SignatureEnvelope");
  }
  const env = value;
  if (typeof env.sig !== "string" || env.sig.length === 0) {
    throw new Error("Invalid SignatureEnvelope.sig");
  }
  if (typeof env.publicKey !== "string" || env.publicKey.length === 0) {
    throw new Error("Invalid SignatureEnvelope.publicKey");
  }
  if (env.githubUser !== void 0 && typeof env.githubUser !== "string") {
    throw new Error("Invalid SignatureEnvelope.githubUser");
  }
}
async function upload(data, fileInfo, options = {}) {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  const keyMaterial = generateKey();
  const salt = generateSalt();
  const iv = generateIV();
  const cryptoKey = await deriveKey(keyMaterial, salt);
  const wantsSignature = options.signature !== void 0 || options.sign !== void 0;
  const signedContent = wantsSignature ? decodeUtf8Strict(data) : void 0;
  let signatureEnvelope;
  if (options.signature !== void 0) {
    assertSignatureEnvelope(options.signature);
    signatureEnvelope = options.signature;
  } else if (options.sign) {
    if ("signer" in options.sign) {
      const envelope = await options.sign.signer(data);
      assertSignatureEnvelope(envelope);
      signatureEnvelope = envelope;
    } else {
      signatureEnvelope = await createSignatureEnvelope(data, options.sign.privateKey, options.sign.publicKey, {
        githubUser: options.sign.githubUser
      });
      assertSignatureEnvelope(signatureEnvelope);
    }
  }
  if (wantsSignature) {
    assert(signatureEnvelope !== void 0, "Signature requested but no signature envelope was produced");
  }
  let plaintext;
  if (signatureEnvelope) {
    assert(signedContent !== void 0, "Signed content string missing");
    const signed = {
      content: signedContent,
      sig: signatureEnvelope
    };
    plaintext = new TextEncoder().encode(JSON.stringify(signed));
  } else {
    plaintext = data;
  }
  const payload = await encrypt(plaintext, cryptoKey, iv);
  const metaJson = JSON.stringify(fileInfo);
  const metaBytes = new TextEncoder().encode(metaJson);
  const metaIv = generateIV();
  const encryptedMeta = await encrypt(metaBytes, cryptoKey, metaIv);
  const uploadMeta = {
    salt: base64Encode(salt),
    iv: base64Encode(iv),
    encryptedMeta: base64Encode(new Uint8Array([...metaIv, ...encryptedMeta]))
  };
  const headers = {
    "Content-Type": "application/octet-stream",
    "X-Lattice-Meta": btoa(JSON.stringify(uploadMeta))
  };
  if (options.expiresAt !== void 0) {
    let expiresDate;
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
    body: payload.buffer
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
    ...result.expiresAt && { expiresAt: result.expiresAt }
  };
}
async function download(url, key, options = {}) {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  let id;
  let keyMaterial;
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
  const encryptedMetaWithIv = base64Decode(uploadMeta.encryptedMeta);
  const metaIv = encryptedMetaWithIv.slice(0, 12);
  const encryptedMetaData = encryptedMetaWithIv.slice(12);
  const metaBytes = await decrypt(encryptedMetaData, cryptoKey, metaIv);
  const info = JSON.parse(new TextDecoder().decode(metaBytes));
  const decrypted = await decrypt(encryptedData, cryptoKey, iv);
  if (decrypted[0] === 123) {
    try {
      const jsonStr = new TextDecoder().decode(decrypted);
      const parsed = JSON.parse(jsonStr);
      if (typeof parsed.content === "string" && parsed.sig) {
        const data = new TextEncoder().encode(parsed.content);
        const signature = parsed.sig;
        return { data, info, signature };
      }
    } catch {
    }
  }
  return { data: decrypted, info };
}
async function getMeta(url, key, options = {}) {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  let id;
  let keyMaterial;
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
  const info = JSON.parse(new TextDecoder().decode(metaBytes));
  return { info, size: meta.size };
}
function parseUrl(url) {
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
function buildUrl(id, key, baseUrl = DEFAULT_BASE_URL) {
  return `${baseUrl}/${id}#${key}`;
}
async function deleteFile(id, mutateKey, options = {}) {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  const response = await fetch(`${baseUrl}/${id}`, {
    method: "DELETE",
    headers: {
      "X-Lattice-Mutate-Key": mutateKey
    }
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Delete failed" }));
    throw new Error(error.error || "Delete failed");
  }
}
async function setExpiration(id, mutateKey, expiresAt, options = {}) {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  let expiresHeader;
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
      "X-Lattice-Expires": expiresHeader
    }
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Set expiration failed" }));
    throw new Error(error.error || "Set expiration failed");
  }
  return response.json();
}

export { base64Decode, base64Encode, base64UrlDecode, base64UrlEncode, buildUrl, computeFingerprint, createSignatureEnvelope, decrypt, deleteFile, deriveKey, download, encrypt, formatFingerprint, generateIV, generateId, generateKey, generateMutateKey, generateSalt, getMeta, parsePublicKey, parseUrl, setExpiration, signECDSA, signEd25519, upload, verifySignature };
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map