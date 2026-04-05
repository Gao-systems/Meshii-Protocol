/**
 * W3C Verifiable Credential — Meshii Identity (Section 5.3).
 *
 * Proof type:  Ed25519Signature2020
 * Proof value: base58btc-encoded Ed25519 signature
 * Issuer:      did:web:id.gao.domains
 *
 * Signing input: deterministic JSON (recursively sorted keys).
 * NOTE: This is a simplified canonicalization. Full JSON-LD RDNA
 * canonicalization is out of scope (requires ~100kB processor
 * incompatible with CF Workers zero-dep requirement).
 */

import { ed25519Sign, ed25519Verify, encodeBase58, decodeBase58 } from "../crypto/primitives.js";
import type {
  MeshiiIdentityCredential,
  MeshiiIdentityCredentialSigned,
  VCProof,
} from "../types/index.js";

export const VC_ISSUER = "did:web:id.gao.domains";
export const VC_CONTEXT = [
  "https://www.w3.org/2018/credentials/v1",
  "https://meshii.gao/credentials/v2",
];

/** Recursively sort object keys for deterministic JSON serialization. */
function canonicalJSON(obj: unknown): string {
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalJSON).join(",") + "]";
  }
  if (obj !== null && typeof obj === "object") {
    const rec = obj as Record<string, unknown>;
    const sorted = Object.keys(rec)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalJSON(rec[k]));
    return "{" + sorted.join(",") + "}";
  }
  return JSON.stringify(obj);
}

function signingBytes(vc: MeshiiIdentityCredential): Uint8Array {
  // Remove proof field before signing
  const copy: Record<string, unknown> = { ...vc };
  delete copy["proof"];
  return new TextEncoder().encode(canonicalJSON(copy));
}

/**
 * Sign a Meshii Identity Credential.
 *
 * @param vc                  Unsigned credential (proof field ignored if present)
 * @param signingKey          Ed25519 private key of the issuer
 * @param verificationMethod  DID URL of the signing key (e.g. did:web:id.gao.domains#key-1)
 */
export function signVC(
  vc: MeshiiIdentityCredential,
  signingKey: Uint8Array,
  verificationMethod: string
): MeshiiIdentityCredentialSigned {
  const input = signingBytes(vc);
  const signature = ed25519Sign(signingKey, input);
  const proof: VCProof = {
    type: "Ed25519Signature2020",
    verificationMethod,
    proofValue: encodeBase58(signature),
  };
  return { ...vc, proof };
}

/**
 * Verify a signed Meshii Identity Credential.
 * Returns false if expired, signature invalid, or proof malformed.
 *
 * @param vc         Signed credential
 * @param verifyKey  Ed25519 public key of the issuer
 */
export function verifyVC(
  vc: MeshiiIdentityCredentialSigned,
  verifyKey: Uint8Array
): boolean {
  if (vc.proof.type !== "Ed25519Signature2020") return false;

  // Check expiry
  if (Date.now() > new Date(vc.expirationDate).getTime()) return false;

  let signature: Uint8Array;
  try {
    signature = decodeBase58(vc.proof.proofValue);
  } catch {
    return false;
  }

  return ed25519Verify(verifyKey, signingBytes(vc), signature);
}

/**
 * Construct an unsigned MeshiiIdentityCredential.
 * Call signVC() before using.
 *
 * Default TTL: 24 hours (per spec §5.3).
 */
export function buildVC(params: {
  subjectDid: string;
  walletAddress: string;
  meshiiDomain?: string;
  identityKeyPublic: string;
  routingTagSalt: string;
  tier: "wallet" | "domain" | "ephemeral";
  ttlMs?: number;
}): MeshiiIdentityCredential {
  const now = new Date();
  const ttl = params.ttlMs ?? 24 * 60 * 60 * 1000;
  const expiry = new Date(now.getTime() + ttl);

  const credentialSubject: MeshiiIdentityCredential["credentialSubject"] = {
    id: params.subjectDid,
    walletAddress: params.walletAddress,
    identityKeyPublic: params.identityKeyPublic,
    routingTagSalt: params.routingTagSalt,
    tier: params.tier,
  };
  if (params.meshiiDomain !== undefined) {
    credentialSubject.meshiiDomain = params.meshiiDomain;
  }

  return {
    "@context": VC_CONTEXT,
    type: ["VerifiableCredential", "MeshiiIdentityCredential"],
    issuer: VC_ISSUER,
    issuanceDate: now.toISOString(),
    expirationDate: expiry.toISOString(),
    credentialSubject,
  };
}
