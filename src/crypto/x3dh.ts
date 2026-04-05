/**
 * X3DH — Extended Triple Diffie-Hellman key agreement.
 * Implements Signal X3DH specification (Section 6.1).
 *
 * IK uses Ed25519, converted to X25519 via birational equivalence for DH.
 * SPK and OPK are native X25519.
 *
 * DH function: X25519 (RFC 7748)
 * KDF: HKDF-SHA256 (RFC 5869)
 */

import {
  generateX25519KeyPair,
  x25519DH,
  ed25519PubToX25519,
  ed25519PrivToX25519,
  hkdfSHA256,
  concat,
} from "./primitives.js";
import type {
  IdentityKeyBundlePublic,
  X3DHInitResult,
  X3DHReceiveResult,
} from "../types/index.js";

// Per Signal X3DH spec §2.2: prepend 0xFF * 32 to IKM for domain separation
const F_BYTES = new Uint8Array(32).fill(0xff);
// Zero salt per Signal spec
const ZERO_SALT = new Uint8Array(32);
const X3DH_INFO = "meshii-x3dh-v1";

/**
 * X3DH sender (Alice).
 * Computes the shared secret from the recipient's public key bundle.
 *
 * DH computations (Signal spec §3.3):
 *   DH1 = DH(IK_A→X25519,  SPK_B)
 *   DH2 = DH(EK_A,          IK_B→X25519)
 *   DH3 = DH(EK_A,          SPK_B)
 *   DH4 = DH(EK_A,          OPK_B)   [if OPK available]
 *
 * @param senderIKPriv   Sender's Ed25519 IK private key
 * @param recipientBundle  Recipient's public key bundle
 */
export function x3dhSend(
  senderIKPriv: Uint8Array,
  recipientBundle: IdentityKeyBundlePublic
): X3DHInitResult {
  const EK_A = generateX25519KeyPair();

  const IK_A_x_priv = ed25519PrivToX25519(senderIKPriv);
  const IK_B_x_pub = ed25519PubToX25519(recipientBundle.identityKeyPublic);
  const SPK_B = recipientBundle.signedPreKey.publicKey;

  const DH1 = x25519DH(IK_A_x_priv, SPK_B);
  const DH2 = x25519DH(EK_A.privateKey, IK_B_x_pub);
  const DH3 = x25519DH(EK_A.privateKey, SPK_B);

  let ikm: Uint8Array;
  let usedOPKId: number | undefined;

  if (recipientBundle.oneTimePreKeys.length > 0) {
    const opk = recipientBundle.oneTimePreKeys[0];
    const DH4 = x25519DH(EK_A.privateKey, opk.publicKey);
    ikm = concat([F_BYTES, DH1, DH2, DH3, DH4]);
    DH4.fill(0);
    usedOPKId = opk.keyId;
  } else {
    ikm = concat([F_BYTES, DH1, DH2, DH3]);
  }

  DH1.fill(0);
  DH2.fill(0);
  DH3.fill(0);

  const sharedSecret = hkdfSHA256(ikm, ZERO_SALT, X3DH_INFO, 32);

  const result: X3DHInitResult = {
    sharedSecret,
    ephemeralPublicKey: EK_A.publicKey,
  };
  if (usedOPKId !== undefined) result.usedOPKId = usedOPKId;
  return result;
}

/**
 * X3DH receiver (Bob).
 * Recomputes the shared secret from the sender's ephemeral key.
 *
 * DH computations (mirror of sender):
 *   DH1 = DH(SPK_B,          IK_A→X25519)
 *   DH2 = DH(IK_B→X25519,    EK_A)
 *   DH3 = DH(SPK_B,          EK_A)
 *   DH4 = DH(OPK_B,          EK_A)   [if OPK was used]
 *
 * @param recipientIKPriv    Recipient's Ed25519 IK private key
 * @param recipientSPKPriv   Recipient's X25519 SPK private key
 * @param recipientOPKPriv   Recipient's X25519 OPK private key (if used)
 * @param senderIKPub        Sender's Ed25519 IK public key
 * @param senderEKPub        Sender's ephemeral X25519 public key
 */
export function x3dhReceive(
  recipientIKPriv: Uint8Array,
  recipientSPKPriv: Uint8Array,
  recipientOPKPriv: Uint8Array | undefined,
  senderIKPub: Uint8Array,
  senderEKPub: Uint8Array
): X3DHReceiveResult {
  const IK_A_x_pub = ed25519PubToX25519(senderIKPub);
  const IK_B_x_priv = ed25519PrivToX25519(recipientIKPriv);

  const DH1 = x25519DH(recipientSPKPriv, IK_A_x_pub);
  const DH2 = x25519DH(IK_B_x_priv, senderEKPub);
  const DH3 = x25519DH(recipientSPKPriv, senderEKPub);

  let ikm: Uint8Array;

  if (recipientOPKPriv !== undefined) {
    const DH4 = x25519DH(recipientOPKPriv, senderEKPub);
    ikm = concat([F_BYTES, DH1, DH2, DH3, DH4]);
    DH4.fill(0);
  } else {
    ikm = concat([F_BYTES, DH1, DH2, DH3]);
  }

  DH1.fill(0);
  DH2.fill(0);
  DH3.fill(0);

  const sharedSecret = hkdfSHA256(ikm, ZERO_SALT, X3DH_INFO, 32);
  return { sharedSecret };
}
