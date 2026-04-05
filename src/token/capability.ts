/**
 * Relay capability token — Ed25519 signed (Section 9.3).
 *
 * Pure logic: token construction, signing, and verification.
 * No fetch, no transport dependency, no wallet coupling.
 *
 * TTL: max 5 minutes per spec.
 * Nonce: 16-byte hex, single-use (relay enforces nonce deduplication).
 */

import {
  ed25519Sign,
  ed25519Verify,
  randomBytes,
  bytesToHex,
  hexToBytes,
} from "../crypto/primitives.js";
import type {
  SignalingCapabilityToken,
  SignedCapabilityToken,
} from "../types/index.js";

const MAX_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes per spec §9.3

/** Deterministic JSON with sorted keys — canonical signing input. */
function canonicalPayload(token: SignalingCapabilityToken): Uint8Array {
  const sorted: Record<string, unknown> = {};
  for (const key of (Object.keys(token) as (keyof SignalingCapabilityToken)[]).sort()) {
    sorted[key] = token[key];
  }
  return new TextEncoder().encode(JSON.stringify(sorted));
}

/**
 * Sign a capability token with an Ed25519 deployment key.
 *
 * @param token      Unsigned token payload
 * @param signingKey Ed25519 private key of the server/deployment
 */
export function signCapabilityToken(
  token: SignalingCapabilityToken,
  signingKey: Uint8Array
): SignedCapabilityToken {
  const input = canonicalPayload(token);
  const signature = ed25519Sign(signingKey, input);
  return { ...token, signature: bytesToHex(signature) };
}

/**
 * Verify a signed capability token.
 *
 * Checks: Ed25519 signature · not expired · valid role
 *
 * @param token      Signed token
 * @param verifyKey  Ed25519 public key of the deployment
 */
export function verifyCapabilityToken(
  token: SignedCapabilityToken,
  verifyKey: Uint8Array
): boolean {
  if (Date.now() > token.expires_at) return false;
  if (token.role !== "caller" && token.role !== "callee") return false;

  let sigBytes: Uint8Array;
  try {
    sigBytes = hexToBytes(token.signature);
  } catch {
    return false;
  }

  // Reconstruct payload without signature field
  const { signature: _sig, ...payload } = token;
  void _sig;
  return ed25519Verify(verifyKey, canonicalPayload(payload), sigBytes);
}

/**
 * Build an unsigned capability token.
 *
 * @param callId        UUIDv4 call identifier
 * @param routingTag    Recipient routing tag
 * @param role          'caller' or 'callee'
 * @param vcSubjectDid  did:ethr:<address> of the VC holder
 * @param ttlMs         Token TTL in ms (clamped to 5 minutes max)
 */
export function buildCapabilityToken(
  callId: string,
  routingTag: string,
  role: "caller" | "callee",
  vcSubjectDid: string,
  ttlMs: number = MAX_TOKEN_TTL_MS
): SignalingCapabilityToken {
  const now = Date.now();
  return {
    call_id: callId,
    routing_tag: routingTag,
    role,
    vc_subject_did: vcSubjectDid,
    issued_at: now,
    expires_at: now + Math.min(ttlMs, MAX_TOKEN_TTL_MS),
    nonce: bytesToHex(randomBytes(16)),
  };
}

/** Generate a 16-byte hex nonce. Single-use — relay must deduplicate. */
export function generateTokenNonce(): string {
  return bytesToHex(randomBytes(16));
}
