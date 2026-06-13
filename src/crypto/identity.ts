/**
 * Identity Key derivation and key bundle generation.
 * All IK operations are client-side only (RF-04, MESHINV-07).
 *
 * Server role in IK derivation:
 *   1. Verify SIWE (EIP-4361)
 *   2. Return server_ephemeral_X25519_pub
 *   3. Receive IK_pub from client
 *   4. Store IK_pub only
 *
 * Server NEVER: performs ECDH, derives shared_secret, holds IK private key.
 */

import { ed25519 } from "@noble/curves/ed25519";
import {
  generateEd25519KeyPair,
  generateX25519KeyPair,
  ed25519Sign,
  ed25519Verify,
  hkdfSHA256,
  bytesToHex,
  canonicalJSON,
} from "./primitives.js";
import type {
  Ed25519KeyPair,
  IdentityKeyBundle,
  IdentityKeyBundlePublic,
} from "../types/index.js";

/** Domain-separation context for the v2 Signed PreKey signature payload. */
export const SPK_SIG_V2_CONTEXT = "meshii-spk-v2";

/** Default Signed PreKey lifetime: 7 days (per spec §5.4 rotation cadence). */
export const SPK_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Canonical signing input for the v2 Signed PreKey signature.
 *
 * Binds the SPK public key together with its keyId, createdAt and expiresAt
 * under a versioned context string, so a relay cannot serve a stale-but-validly
 * -signed SPK (MESHINV-09 freshness). Deterministic via canonicalJSON (the same
 * canonicalization used for VC and capability-token signing).
 */
function spkSigningPayloadV2(
  spkPublicKey: Uint8Array,
  keyId: number,
  createdAt: number,
  expiresAt: number
): Uint8Array {
  return new TextEncoder().encode(
    canonicalJSON({
      v: SPK_SIG_V2_CONTEXT,
      spk: bytesToHex(spkPublicKey),
      keyId,
      createdAt,
      expiresAt,
    })
  );
}

/**
 * Derive an Identity Key (Ed25519) from a shared ECDH secret.
 *
 * IK = HKDF-SHA256(
 *   ikm:  shared_secret,
 *   salt: UTF8(domain) || nonce,
 *   info: "meshii-identity-v2"
 * )
 *
 * Same wallet + same domain + same nonce → same IK (deterministic).
 * This function runs entirely client-side (RF-04).
 *
 * @param sharedSecret  X25519 ECDH output (from client_ephemeral + server_ephemeral)
 * @param domain        Meshii domain (e.g. "alice.gao") or empty string for Tier 3
 * @param nonce         Per-session nonce (received from server SIWE challenge)
 */
export function deriveIdentityKey(
  sharedSecret: Uint8Array,
  domain: string,
  nonce: Uint8Array
): Ed25519KeyPair {
  const enc = new TextEncoder();
  const domainBytes = enc.encode(domain);
  // salt = UTF8(domain) || nonce  (byte concatenation per spec §5.2)
  const salt = new Uint8Array(domainBytes.length + nonce.length);
  salt.set(domainBytes, 0);
  salt.set(nonce, domainBytes.length);

  const ikSeed = hkdfSHA256(sharedSecret, salt, "meshii-identity-v2", 32);
  const publicKey = ed25519.getPublicKey(ikSeed);
  return { privateKey: ikSeed, publicKey };
}

/**
 * Generate a full identity key bundle (Section 5.4).
 *
 * Bundle structure:
 *   IK  — Ed25519 keypair (root of session trust)
 *   SPK — X25519 keypair, signed by IK (rotate every 7 days)
 *   OPK — batch of single-use X25519 keypairs (default: 100)
 *
 * @param opkCount  Number of one-time pre-keys to generate (default: 100)
 */
export function generateIdentityKeyBundle(opkCount = 100): IdentityKeyBundle {
  const identityKey = generateEd25519KeyPair();

  const spkPair = generateX25519KeyPair();
  const keyId = 1;
  const createdAt = Date.now();
  const expiresAt = createdAt + SPK_TTL_MS;
  // v1 (legacy): signs only the SPK public key. Retained for backward compatibility.
  const spkSignature = ed25519Sign(identityKey.privateKey, spkPair.publicKey);
  // v2 (preferred): binds spk + keyId + createdAt + expiresAt under a versioned context.
  const spkSignatureV2 = ed25519Sign(
    identityKey.privateKey,
    spkSigningPayloadV2(spkPair.publicKey, keyId, createdAt, expiresAt)
  );

  const oneTimePreKeys: IdentityKeyBundle["oneTimePreKeys"] = [];
  for (let i = 0; i < opkCount; i++) {
    oneTimePreKeys.push({ keyPair: generateX25519KeyPair(), keyId: i + 1 });
  }

  return {
    identityKey,
    signedPreKey: {
      keyPair: spkPair,
      signature: spkSignature,
      signatureV2: spkSignatureV2,
      keyId,
      createdAt,
      expiresAt,
    },
    oneTimePreKeys,
  };
}

/**
 * Extract the public-only portion of a key bundle (safe to publish to relay).
 */
export function extractPublicBundle(
  bundle: IdentityKeyBundle
): IdentityKeyBundlePublic {
  return {
    identityKeyPublic: bundle.identityKey.publicKey,
    signedPreKey: {
      publicKey: bundle.signedPreKey.keyPair.publicKey,
      signature: bundle.signedPreKey.signature,
      signatureV2: bundle.signedPreKey.signatureV2,
      keyId: bundle.signedPreKey.keyId,
      createdAt: bundle.signedPreKey.createdAt,
      expiresAt: bundle.signedPreKey.expiresAt,
    },
    oneTimePreKeys: bundle.oneTimePreKeys.map((opk) => ({
      publicKey: opk.keyPair.publicKey,
      keyId: opk.keyId,
    })),
  };
}

/**
 * Verify the v1 (legacy) SPK signature: Ed25519(IK_priv, SPK_pub).
 *
 * @deprecated Legacy. This binds ONLY the SPK public key — it does NOT bind
 * keyId/createdAt/expiresAt, so it cannot detect a relay serving a
 * stale-but-validly-signed SPK. Use {@link verifySPKSignatureV2} for freshness.
 * Retained for backward compatibility with bundles that carry only a v1 signature.
 */
export function verifySPKSignature(bundle: IdentityKeyBundlePublic): boolean {
  return ed25519Verify(
    bundle.identityKeyPublic,
    bundle.signedPreKey.publicKey,
    bundle.signedPreKey.signature
  );
}

/**
 * Verify the v2 Signed PreKey signature (preferred).
 *
 * The v2 signature binds spkPublicKey + keyId + createdAt + expiresAt under the
 * "meshii-spk-v2" context, defending against a relay that serves a
 * stale-but-validly-signed SPK (MESHINV-09 freshness).
 *
 * Fail-closed: returns false if the v2 fields are absent, the validity window is
 * malformed (expiresAt <= createdAt or non-finite), the SPK is expired
 * (now > expiresAt), the payload cannot be built, or the signature is invalid.
 *
 * Consumers that require freshness MUST use this and treat a missing/invalid v2
 * signature as rejection — falling back to {@link verifySPKSignature} (v1) does
 * not protect against old-SPK replay.
 *
 * @param bundle    Public identity key bundle
 * @param opts.now  Current time in Unix ms (default: Date.now())
 */
export function verifySPKSignatureV2(
  bundle: IdentityKeyBundlePublic,
  opts?: { now?: number }
): boolean {
  const spk = bundle.signedPreKey;
  if (spk.signatureV2 === undefined || spk.expiresAt === undefined) return false;
  if (!Number.isFinite(spk.createdAt) || !Number.isFinite(spk.expiresAt)) return false;
  if (spk.expiresAt <= spk.createdAt) return false;
  const now = opts?.now ?? Date.now();
  if (!Number.isFinite(now)) return false; // reject NaN/±Infinity clock values
  if (now > spk.expiresAt) return false;
  try {
    const payload = spkSigningPayloadV2(spk.publicKey, spk.keyId, spk.createdAt, spk.expiresAt);
    return ed25519Verify(bundle.identityKeyPublic, payload, spk.signatureV2);
  } catch {
    return false;
  }
}

/**
 * Sign a v2 Signed PreKey signature (the canonical counterpart of
 * {@link verifySPKSignatureV2}).
 *
 * Signs the SAME canonical payload that verifySPKSignatureV2 reconstructs — it
 * binds spkPublicKey + keyId + createdAt + expiresAt under the "meshii-spk-v2"
 * context — so consumers (e.g. key-package registration that signs an SPK with an
 * existing identity key) do not need to duplicate the canonical payload.
 *
 * `expiresAt` is explicit; callers typically pass `createdAt + SPK_TTL_MS`.
 * Returns the raw Ed25519 signature bytes (assign to
 * `signedPreKey.signatureV2`).
 *
 * @param identityKeyPrivate  IK Ed25519 private key (signs the SPK)
 * @param spkPublicKey        X25519 Signed PreKey public key
 * @param keyId               SPK key id
 * @param createdAt           SPK creation time (Unix ms)
 * @param expiresAt           SPK expiry (Unix ms)
 */
export function signSPKSignatureV2(
  identityKeyPrivate: Uint8Array,
  spkPublicKey: Uint8Array,
  keyId: number,
  createdAt: number,
  expiresAt: number
): Uint8Array {
  return ed25519Sign(
    identityKeyPrivate,
    spkSigningPayloadV2(spkPublicKey, keyId, createdAt, expiresAt)
  );
}
