/**
 * Double Ratchet Algorithm — Signal specification §2–4.
 *
 * Provides forward secrecy (symmetric-key ratchet) and break-in recovery
 * (Diffie-Hellman ratchet). Handles out-of-order delivery via skipped
 * message key cache (up to MAX_SKIP keys).
 *
 * Root chain KDF:      HKDF-SHA256
 * Symmetric chain KDF: HMAC-SHA256
 * Message encryption:  AES-256-GCM, 96-bit random nonce per message
 */

import {
  generateX25519KeyPair,
  x25519DH,
  hkdfSHA256,
  hmacSHA256,
  aesGCMEncrypt,
  aesGCMDecrypt,
  concat,
  uint32ToBytes,
  bytesToHex,
  bytesEqual,
} from "./primitives.js";
import type {
  RatchetState,
  EncryptedMessage,
  X25519KeyPair,
} from "../types/index.js";

/** Maximum number of skipped message keys to store (Signal spec). */
const MAX_SKIP = 1000;

const KDF_RK_INFO = "meshii-ratchet-rk-v1";
// HMAC constants per Signal Double Ratchet spec
const CONSTANT_01 = new Uint8Array([0x01]); // message key
const CONSTANT_02 = new Uint8Array([0x02]); // chain key advancement

// ---------------------------------------------------------------------------
// KDF functions
// ---------------------------------------------------------------------------

function kdfRK(
  rootKey: Uint8Array,
  dhOutput: Uint8Array
): { newRootKey: Uint8Array; newChainKey: Uint8Array } {
  const out = hkdfSHA256(dhOutput, rootKey, KDF_RK_INFO, 64);
  return { newRootKey: out.slice(0, 32), newChainKey: out.slice(32, 64) };
}

function kdfCK(chainKey: Uint8Array): {
  messageKey: Uint8Array;
  newChainKey: Uint8Array;
} {
  return {
    messageKey: hmacSHA256(chainKey, CONSTANT_01),
    newChainKey: hmacSHA256(chainKey, CONSTANT_02),
  };
}

// ---------------------------------------------------------------------------
// Header serialization — 40 bytes: 32 DH pub + 4 msgCount + 4 prevCount
// ---------------------------------------------------------------------------

function serializeHeader(header: EncryptedMessage["header"]): Uint8Array {
  return concat([
    header.dhPublicKey,
    uint32ToBytes(header.messageCount),
    uint32ToBytes(header.previousCount),
  ]);
}

function skippedKey(dhPub: Uint8Array, n: number): string {
  return `${bytesToHex(dhPub)}:${n}`;
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/**
 * Initialize Double Ratchet for the session initiator (Alice).
 * Called after X3DH with the shared secret and Bob's signed pre-key public key.
 */
export function initRatchetAlice(
  sharedSecret: Uint8Array,
  recipientSPKPub: Uint8Array
): RatchetState {
  const DHs = generateX25519KeyPair();
  const dh = x25519DH(DHs.privateKey, recipientSPKPub);
  const { newRootKey, newChainKey } = kdfRK(sharedSecret, dh);
  dh.fill(0);

  return {
    rootKey: newRootKey,
    sendingChainKey: newChainKey,
    receivingChainKey: null,
    sendingDHKey: DHs,
    receivingDHPublicKey: recipientSPKPub,
    sendMessageCount: 0,
    receiveMessageCount: 0,
    previousSendCount: 0,
    skippedMessageKeys: new Map(),
  };
}

/**
 * Initialize Double Ratchet for the session responder (Bob).
 * Called after X3DH with the shared secret and Bob's SPK key pair.
 */
export function initRatchetBob(
  sharedSecret: Uint8Array,
  spkKeyPair: X25519KeyPair
): RatchetState {
  return {
    rootKey: sharedSecret,
    sendingChainKey: null,
    receivingChainKey: null,
    sendingDHKey: spkKeyPair,
    receivingDHPublicKey: null,
    sendMessageCount: 0,
    receiveMessageCount: 0,
    previousSendCount: 0,
    skippedMessageKeys: new Map(),
  };
}

// ---------------------------------------------------------------------------
// DH Ratchet step (internal)
// ---------------------------------------------------------------------------

function dhRatchet(state: RatchetState, receivedDHPub: Uint8Array): void {
  state.previousSendCount = state.sendMessageCount;
  state.sendMessageCount = 0;
  state.receiveMessageCount = 0;
  state.receivingDHPublicKey = receivedDHPub;

  const dh1 = x25519DH(state.sendingDHKey.privateKey, receivedDHPub);
  const { newRootKey: rk1, newChainKey: ckr } = kdfRK(state.rootKey, dh1);
  dh1.fill(0);
  state.rootKey = rk1;
  state.receivingChainKey = ckr;

  state.sendingDHKey = generateX25519KeyPair();
  const dh2 = x25519DH(state.sendingDHKey.privateKey, receivedDHPub);
  const { newRootKey: rk2, newChainKey: cks } = kdfRK(state.rootKey, dh2);
  dh2.fill(0);
  state.rootKey = rk2;
  state.sendingChainKey = cks;
}

// ---------------------------------------------------------------------------
// Skip message keys (out-of-order delivery)
// ---------------------------------------------------------------------------

function skipMessageKeys(state: RatchetState, until: number): void {
  const gap = until - state.receiveMessageCount;
  if (gap > MAX_SKIP) {
    throw new Error(`MAX_SKIP exceeded: gap ${gap} > ${MAX_SKIP}`);
  }
  while (
    state.receivingChainKey !== null &&
    state.receiveMessageCount < until
  ) {
    const { messageKey, newChainKey } = kdfCK(state.receivingChainKey);
    state.receivingChainKey = newChainKey;
    state.skippedMessageKeys.set(
      skippedKey(state.receivingDHPublicKey!, state.receiveMessageCount),
      messageKey
    );
    state.receiveMessageCount++;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encrypt a message. Advances the sending chain.
 * Mutates `state` in place.
 *
 * @param state           Ratchet state
 * @param plaintext       Message bytes to encrypt
 * @param associatedData  Additional authenticated data (default: empty)
 */
export async function ratchetEncrypt(
  state: RatchetState,
  plaintext: Uint8Array,
  associatedData: Uint8Array = new Uint8Array(0)
): Promise<EncryptedMessage> {
  if (state.sendingChainKey === null) {
    throw new Error("Sending chain not initialized — call initRatchetAlice first");
  }

  const { messageKey, newChainKey } = kdfCK(state.sendingChainKey);
  state.sendingChainKey = newChainKey;

  const header: EncryptedMessage["header"] = {
    dhPublicKey: state.sendingDHKey.publicKey,
    messageCount: state.sendMessageCount,
    previousCount: state.previousSendCount,
  };
  state.sendMessageCount++;

  const aad = concat([associatedData, serializeHeader(header)]);
  const { ciphertext, nonce } = await aesGCMEncrypt(messageKey, plaintext, aad);
  messageKey.fill(0);

  return { header, ciphertext, nonce };
}

/**
 * Decrypt a message. May perform a DH ratchet step.
 * Mutates `state` in place.
 *
 * @param state           Ratchet state
 * @param message         Encrypted message from ratchetEncrypt()
 * @param associatedData  Must match the value used during encryption
 */
export async function ratchetDecrypt(
  state: RatchetState,
  message: EncryptedMessage,
  associatedData: Uint8Array = new Uint8Array(0)
): Promise<Uint8Array> {
  const { header, ciphertext, nonce } = message;
  const aad = concat([associatedData, serializeHeader(header)]);

  // Try skipped message keys first
  const sk = skippedKey(header.dhPublicKey, header.messageCount);
  const skippedMK = state.skippedMessageKeys.get(sk);
  if (skippedMK !== undefined) {
    state.skippedMessageKeys.delete(sk);
    const plaintext = await aesGCMDecrypt(skippedMK, ciphertext, nonce, aad);
    skippedMK.fill(0);
    return plaintext;
  }

  // DH ratchet step if new DH key received
  const isDifferentDH =
    state.receivingDHPublicKey === null ||
    !bytesEqual(header.dhPublicKey, state.receivingDHPublicKey);

  if (isDifferentDH) {
    skipMessageKeys(state, header.previousCount);
    dhRatchet(state, header.dhPublicKey);
  }

  skipMessageKeys(state, header.messageCount);

  if (state.receivingChainKey === null) {
    throw new Error("Receiving chain not initialized after DH ratchet");
  }

  const { messageKey, newChainKey } = kdfCK(state.receivingChainKey);
  state.receivingChainKey = newChainKey;
  state.receiveMessageCount++;

  const plaintext = await aesGCMDecrypt(messageKey, ciphertext, nonce, aad);
  messageKey.fill(0);
  return plaintext;
}
