// Test-only helpers for deterministic vectors.
//
// The public crypto API intentionally exposes only generateX25519KeyPair()
// (which uses CSPRNG randomness). To build deterministic X25519 keypairs from
// fixed test scalars we derive the public key with the SAME underlying library
// the protocol itself depends on (@noble/curves), in test-only scope. This is
// not a monkey-patch and does not touch globalThis.crypto or any src/ code.
import { x25519 } from "@noble/curves/ed25519";

/** Deterministic X25519 public key from a fixed 32-byte scalar (test-only). */
export function x25519PublicFromScalar(scalar: Uint8Array): Uint8Array {
  return x25519.getPublicKey(scalar);
}

// X3DH domain-separation constants, mirrored from src/crypto/x3dh.ts for the
// independent (from-first-principles) recomputation cross-check. If src ever
// changes these, the cross-check in vectors.test.ts diverges from x3dhReceive
// and the test fails — which is the intended tripwire.
export const X3DH_F_BYTES = new Uint8Array(32).fill(0xff);
export const X3DH_ZERO_SALT = new Uint8Array(32);
export const X3DH_INFO = "meshii-x3dh-v1";
