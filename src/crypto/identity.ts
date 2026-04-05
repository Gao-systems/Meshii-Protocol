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
} from "./primitives.js";
import type {
  Ed25519KeyPair,
  IdentityKeyBundle,
  IdentityKeyBundlePublic,
} from "../types/index.js";

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
  const spkSignature = ed25519Sign(identityKey.privateKey, spkPair.publicKey);

  const oneTimePreKeys: IdentityKeyBundle["oneTimePreKeys"] = [];
  for (let i = 0; i < opkCount; i++) {
    oneTimePreKeys.push({ keyPair: generateX25519KeyPair(), keyId: i + 1 });
  }

  return {
    identityKey,
    signedPreKey: {
      keyPair: spkPair,
      signature: spkSignature,
      keyId: 1,
      createdAt: Date.now(),
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
      keyId: bundle.signedPreKey.keyId,
      createdAt: bundle.signedPreKey.createdAt,
    },
    oneTimePreKeys: bundle.oneTimePreKeys.map((opk) => ({
      publicKey: opk.keyPair.publicKey,
      keyId: opk.keyId,
    })),
  };
}

/**
 * Verify the SPK signature in a public bundle.
 * Must return true before using the bundle for X3DH (MESHINV-09).
 */
export function verifySPKSignature(bundle: IdentityKeyBundlePublic): boolean {
  return ed25519Verify(
    bundle.identityKeyPublic,
    bundle.signedPreKey.publicKey,
    bundle.signedPreKey.signature
  );
}
