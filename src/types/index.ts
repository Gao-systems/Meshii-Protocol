/**
 * @meshii/protocol — Type definitions
 * Meshii Protocol v2.1 (MESHINV-01–12)
 */

/** Ed25519 key pair — identity signing, VC proofs, capability tokens */
export type Ed25519KeyPair = {
  privateKey: Uint8Array; // 32-byte scalar seed
  publicKey: Uint8Array;  // 32-byte compressed point
};

/** X25519 key pair — Diffie-Hellman (X3DH, Double Ratchet) */
export type X25519KeyPair = {
  privateKey: Uint8Array; // 32-byte scalar
  publicKey: Uint8Array;  // 32-byte u-coordinate
};

/**
 * Full identity key bundle (Section 5.4).
 * Contains private key material — NEVER transmit over network.
 * Use extractPublicBundle() to get the shareable public portion.
 */
export type IdentityKeyBundle = {
  identityKey: Ed25519KeyPair;
  signedPreKey: {
    keyPair: X25519KeyPair;
    signature: Uint8Array; // Ed25519(IK_priv, SPK_pub)
    keyId: number;
    createdAt: number;     // Unix ms — rotate every 7 days per spec
  };
  oneTimePreKeys: Array<{
    keyPair: X25519KeyPair;
    keyId: number;
  }>;
};

/** Public portion of an identity key bundle — safe to publish to relay */
export type IdentityKeyBundlePublic = {
  identityKeyPublic: Uint8Array;
  signedPreKey: {
    publicKey: Uint8Array;
    signature: Uint8Array;
    keyId: number;
    createdAt: number;
  };
  oneTimePreKeys: Array<{
    publicKey: Uint8Array;
    keyId: number;
  }>;
};

/** Result of X3DH sender-side computation */
export type X3DHInitResult = {
  sharedSecret: Uint8Array;       // 32-byte shared secret
  ephemeralPublicKey: Uint8Array; // Sender's ephemeral X25519 public key (send to recipient)
  usedOPKId?: number;             // OPK consumed, if any (relay must mark as used)
};

/** Result of X3DH receiver-side computation */
export type X3DHReceiveResult = {
  sharedSecret: Uint8Array; // 32-byte shared secret (must equal sender's)
};

/**
 * Double Ratchet state (Signal spec §2).
 * Caller is responsible for serialization and persistence.
 * Zero all Uint8Array fields after session end.
 */
export type RatchetState = {
  rootKey: Uint8Array;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  sendingDHKey: X25519KeyPair;
  receivingDHPublicKey: Uint8Array | null;
  sendMessageCount: number;
  receiveMessageCount: number;
  previousSendCount: number;
  /** Key format: `${dhPublicKeyHex}:${messageCount}` */
  skippedMessageKeys: Map<string, Uint8Array>;
};

/** Encrypted message produced by ratchetEncrypt() */
export type EncryptedMessage = {
  header: {
    dhPublicKey: Uint8Array; // 32 bytes
    messageCount: number;
    previousCount: number;
  };
  ciphertext: Uint8Array; // AES-256-GCM output (includes 16-byte auth tag)
  nonce: Uint8Array;      // 96-bit AES-GCM nonce (unique per message)
};

/**
 * W3C Verifiable Credential — Meshii Identity (Section 5.3).
 * Issuer: did:web:id.gao.domains
 * TTL: 24 hours
 * Storage: client-side only (never server-side)
 */
export type MeshiiIdentityCredential = {
  "@context": string[];
  type: string[];
  issuer: string;
  issuanceDate: string;   // ISO 8601
  expirationDate: string; // ISO 8601
  credentialSubject: {
    id: string;             // did:ethr:<address>
    walletAddress: string;
    meshiiDomain?: string;  // e.g. alice.gao
    identityKeyPublic: string;
    routingTagSalt: string;
    tier: "wallet" | "domain" | "ephemeral";
  };
  proof?: VCProof;
};

export type VCProof = {
  type: "Ed25519Signature2020";
  verificationMethod: string;
  proofValue: string; // base58btc-encoded Ed25519 signature
};

/** MeshiiIdentityCredential with proof field guaranteed present */
export type MeshiiIdentityCredentialSigned = Omit<MeshiiIdentityCredential, "proof"> & {
  proof: VCProof;
};

/** EIP-4361 SIWE message construction parameters (Section 5.2) */
export type SIWEMessageParams = {
  domain: string;
  address: string;
  statement?: string;
  uri: string;
  version: string;
  chainId: number;
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  resources?: string[];
};

/** Relay capability token payload before signing (Section 9.3) */
export type SignalingCapabilityToken = {
  call_id: string;
  routing_tag: string;
  role: "caller" | "callee";
  vc_subject_did: string;
  issued_at: number;   // Unix ms
  expires_at: number;  // Unix ms — max TTL: 5 minutes
  nonce: string;       // 16-byte hex — single-use
};

/** Signed relay capability token */
export type SignedCapabilityToken = SignalingCapabilityToken & {
  signature: string; // hex-encoded Ed25519 signature
};

/** Relay envelope structure (Section 7.2) */
export type RelayEnvelope = {
  envelope_id: string;     // UUIDv4
  routing_tag: string;     // HMAC-SHA256(IK, recipient_id || nonce)
  ciphertext: Uint8Array;  // Double Ratchet encrypted payload
  ttl_expires_at: number;  // Unix ms — max now + 7 days
  created_at: number;      // Unix ms
};
