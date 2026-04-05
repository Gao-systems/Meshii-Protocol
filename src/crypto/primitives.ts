/**
 * Low-level cryptographic primitives for Meshii Protocol.
 *
 * Constraints (MESHINV-04, SECURITY.md §5, GAO SECURITY §15):
 *   - No Math.random() for any cryptographic purpose
 *   - No Node.js crypto module
 *   - No Buffer — Uint8Array only
 *   - Randomness: globalThis.crypto.getRandomValues only
 *   - AES-GCM: globalThis.crypto.subtle only
 *   - Curves/hashes: @noble/curves + @noble/hashes only
 */

import { ed25519, x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import type { Ed25519KeyPair, X25519KeyPair } from "../types/index.js";

export { bytesToHex, hexToBytes };

// ---------------------------------------------------------------------------
// Randomness — CSPRNG only (§6.2)
// ---------------------------------------------------------------------------

/** Returns `length` cryptographically random bytes. Never uses Math.random(). */
export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

// ---------------------------------------------------------------------------
// Ed25519 — RFC 8032
// ---------------------------------------------------------------------------

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** Derive Ed25519 public key from a 32-byte private key seed. */
export function ed25519GetPublicKey(privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKey);
}

/** Sign a message. Signature is deterministic per RFC 8032 §5.1.6. */
export function ed25519Sign(
  privateKey: Uint8Array,
  message: Uint8Array
): Uint8Array {
  return ed25519.sign(message, privateKey);
}

/** Verify an Ed25519 signature. Returns false (not throws) on invalid input. */
export function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// X25519 — RFC 7748
// ---------------------------------------------------------------------------

export function generateX25519KeyPair(): X25519KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** X25519 Diffie-Hellman. */
export function x25519DH(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

/**
 * Convert Ed25519 public key → X25519 (Montgomery form).
 * Used in X3DH to perform DH with IK (birational equivalence of Edwards/Montgomery curves).
 */
export function ed25519PubToX25519(ed25519Pub: Uint8Array): Uint8Array {
  return ed25519.utils.toMontgomery(ed25519Pub);
}

/**
 * Convert Ed25519 private key → X25519 scalar.
 * Used in X3DH to perform DH with IK.
 */
export function ed25519PrivToX25519(ed25519Priv: Uint8Array): Uint8Array {
  return ed25519.utils.toMontgomerySecret(ed25519Priv);
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 — RFC 5869
// ---------------------------------------------------------------------------

export function hkdfSHA256(
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  info: string,
  length: number
): Uint8Array {
  return hkdf(sha256, inputKeyMaterial, salt, new TextEncoder().encode(info), length);
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 — RFC 2104
// ---------------------------------------------------------------------------

export function hmacSHA256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

// ---------------------------------------------------------------------------
// AES-256-GCM — NIST SP 800-38D (WebCrypto)
// ---------------------------------------------------------------------------

/**
 * Encrypt with AES-256-GCM. Nonce is 96-bit random, generated fresh per call.
 * Nonce is NEVER reused — a new random nonce is generated on every invocation.
 */
/** Copy a Uint8Array into a fresh ArrayBuffer — required by WebCrypto BufferSource constraint. */
function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

export async function aesGCMEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  const nonce = randomBytes(12); // 96-bit — never reused
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toArrayBuffer(key),
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );
  const params: { name: string; iv: ArrayBuffer; additionalData?: ArrayBuffer } = {
    name: "AES-GCM",
    iv: toArrayBuffer(nonce),
  };
  if (aad !== undefined) params.additionalData = toArrayBuffer(aad);
  const encrypted = await globalThis.crypto.subtle.encrypt(
    params as unknown as AlgorithmIdentifier,
    cryptoKey,
    toArrayBuffer(plaintext)
  );
  return { ciphertext: new Uint8Array(encrypted), nonce };
}

/** Decrypt AES-256-GCM ciphertext. Throws if authentication fails. */
export async function aesGCMDecrypt(
  key: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    toArrayBuffer(key),
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  const params: { name: string; iv: ArrayBuffer; additionalData?: ArrayBuffer } = {
    name: "AES-GCM",
    iv: toArrayBuffer(nonce),
  };
  if (aad !== undefined) params.additionalData = toArrayBuffer(aad);
  const decrypted = await globalThis.crypto.subtle.decrypt(
    params as unknown as AlgorithmIdentifier,
    cryptoKey,
    toArrayBuffer(ciphertext)
  );
  return new Uint8Array(decrypted);
}

// ---------------------------------------------------------------------------
// base58btc — inline implementation (no external dependency)
// Used for W3C VC Ed25519Signature2020 proof values (Section 5.3)
// ---------------------------------------------------------------------------

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function encodeBase58(bytes: Uint8Array): string {
  let leadingZeros = 0;
  for (const byte of bytes) {
    if (byte !== 0) break;
    leadingZeros++;
  }
  let num = 0n;
  for (const byte of bytes) {
    num = num * 256n + BigInt(byte);
  }
  let result = "";
  while (num > 0n) {
    const remainder = num % 58n;
    result = BASE58_ALPHABET[Number(remainder)] + result;
    num = num / 58n;
  }
  return "1".repeat(leadingZeros) + result;
}

export function decodeBase58(str: string): Uint8Array {
  let num = 0n;
  let leadingZeros = 0;
  let pastLeading = false;
  for (const char of str) {
    if (char === "1" && !pastLeading) {
      leadingZeros++;
      continue;
    }
    pastLeading = true;
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`Invalid base58 character: ${char}`);
    num = num * 58n + BigInt(idx);
  }
  const result: number[] = [];
  while (num > 0n) {
    result.unshift(Number(num % 256n));
    num = num / 256n;
  }
  return new Uint8Array([...new Array(leadingZeros).fill(0), ...result]);
}

// ---------------------------------------------------------------------------
// Byte utilities
// ---------------------------------------------------------------------------

export function concat(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

/** Encode uint32 as 4 big-endian bytes. */
export function uint32ToBytes(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, n, false);
  return buf;
}

/** Constant-time byte comparison. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= a[i] ^ b[i];
  return acc === 0;
}
