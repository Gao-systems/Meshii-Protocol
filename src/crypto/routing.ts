/**
 * Routing tag computation (Section 7.2).
 *
 * routing_tag = HMAC-SHA256(IK_priv, recipient_id || nonce)
 *
 * The routing tag is opaque to the relay — it never links a tag to an identity
 * (MESHINV-10). The nonce prevents correlation across messages.
 */

import { hmacSHA256, randomBytes, concat, bytesToHex } from "./primitives.js";

/**
 * Compute a pseudonymous routing tag.
 *
 * @param identityKeyPrivate  Ed25519 private key used as HMAC key
 * @param recipientId         Recipient identifier (did:ethr or routing tag hex)
 * @param nonce               Per-tag random nonce (prevents correlation)
 * @returns Hex-encoded routing tag
 */
export function computeRoutingTag(
  identityKeyPrivate: Uint8Array,
  recipientId: string,
  nonce: Uint8Array
): string {
  const enc = new TextEncoder();
  const data = concat([enc.encode(recipientId), nonce]);
  return bytesToHex(hmacSHA256(identityKeyPrivate, data));
}

/** Generate a 16-byte random nonce for routing tag computation. */
export function generateRoutingTagNonce(): Uint8Array {
  return randomBytes(16);
}
