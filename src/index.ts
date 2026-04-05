/**
 * @meshii/protocol — Public API
 *
 * Meshii Protocol v2.1 cryptographic primitives.
 * Runtime targets: Browser · Cloudflare Workers · Node.js 18+
 *
 * All crypto: @noble/curves + @noble/hashes + WebCrypto (globalThis.crypto)
 * Zero GPL/LGPL/AGPL (MESHINV-11)
 */

export type {
  Ed25519KeyPair,
  X25519KeyPair,
  IdentityKeyBundle,
  IdentityKeyBundlePublic,
  X3DHInitResult,
  X3DHReceiveResult,
  RatchetState,
  EncryptedMessage,
  MeshiiIdentityCredential,
  MeshiiIdentityCredentialSigned,
  VCProof,
  SIWEMessageParams,
  SignalingCapabilityToken,
  SignedCapabilityToken,
  RelayEnvelope,
} from "./types/index.js";

export {
  // Primitives
  randomBytes,
  generateEd25519KeyPair,
  generateX25519KeyPair,
  ed25519GetPublicKey,
  ed25519Sign,
  ed25519Verify,
  x25519DH,
  ed25519PubToX25519,
  ed25519PrivToX25519,
  hkdfSHA256,
  hmacSHA256,
  aesGCMEncrypt,
  aesGCMDecrypt,
  encodeBase58,
  decodeBase58,
  concat,
  uint32ToBytes,
  bytesEqual,
  bytesToHex,
  hexToBytes,
  // X3DH
  x3dhSend,
  x3dhReceive,
  // Double Ratchet
  initRatchetAlice,
  initRatchetBob,
  ratchetEncrypt,
  ratchetDecrypt,
  // Identity
  deriveIdentityKey,
  generateIdentityKeyBundle,
  extractPublicBundle,
  verifySPKSignature,
  // Routing
  computeRoutingTag,
  generateRoutingTagNonce,
} from "./crypto/index.js";

export {
  // W3C VC
  signVC,
  verifyVC,
  buildVC,
  VC_ISSUER,
  VC_CONTEXT,
} from "./credentials/index.js";

export {
  // SIWE EIP-4361
  buildSIWEMessage,
  generateSIWENonce,
  validateSIWENonce,
} from "./siwe/index.js";

export {
  // Capability tokens
  signCapabilityToken,
  verifyCapabilityToken,
  buildCapabilityToken,
  generateTokenNonce,
} from "./token/index.js";
