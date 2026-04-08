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

// ---------------------------------------------------------------------------
// RatchetState serialization
// ---------------------------------------------------------------------------

const VERSION = 0x01;
const AES_NONCE_LEN = 12;

/**
 * Serialize a RatchetState to a compact binary format.
 *
 * Format (version 0x01):
 *   [0x01 version][rootKey 32B]
 *   [flag 1B][sendingChainKey 32B if present]
 *   [flag 1B][receivingChainKey 32B if present]
 *   [sendingDHKey.privateKey 32B][sendingDHKey.publicKey 32B]
 *   [flag 1B][receivingDHPublicKey 32B if present]
 *   [sendMessageCount 4B BE][receiveMessageCount 4B BE][previousSendCount 4B BE]
 *   [skippedKeys count 4B BE]
 *   for each entry: [keyLen 2B BE][keyBytes N][messageKey 32B]
 *
 * Contains private key material — store securely.
 */
export function serializeRatchetState(state: RatchetState): Uint8Array {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];

  const w8 = (v: number) => new Uint8Array([v]);
  const w16be = (v: number) => new Uint8Array([(v >> 8) & 0xff, v & 0xff]);
  const w32be = (v: number) =>
    new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
  const optional = (v: Uint8Array | null) => {
    if (v === null) return [w8(0x00)];
    return [w8(0x01), v];
  };

  parts.push(w8(VERSION));
  parts.push(state.rootKey);
  parts.push(...optional(state.sendingChainKey));
  parts.push(...optional(state.receivingChainKey));
  parts.push(state.sendingDHKey.privateKey);
  parts.push(state.sendingDHKey.publicKey);
  parts.push(...optional(state.receivingDHPublicKey));
  parts.push(w32be(state.sendMessageCount));
  parts.push(w32be(state.receiveMessageCount));
  parts.push(w32be(state.previousSendCount));
  parts.push(w32be(state.skippedMessageKeys.size));

  for (const [key, mk] of state.skippedMessageKeys) {
    const keyBytes = enc.encode(key);
    parts.push(w16be(keyBytes.length));
    parts.push(keyBytes);
    parts.push(mk);
  }

  return concat(parts);
}

/**
 * Deserialize a RatchetState produced by serializeRatchetState().
 * Throws if the version byte is unrecognized or the buffer is truncated.
 */
export function deserializeRatchetState(bytes: Uint8Array): RatchetState {
  const dec = new TextDecoder();
  let pos = 0;

  const read = (n: number): Uint8Array => {
    if (pos + n > bytes.length) throw new Error("RatchetState: buffer truncated");
    return bytes.slice(pos, (pos += n));
  };
  const r8 = (): number => read(1)[0];
  const r16be = (): number => { const b = read(2); return (b[0] << 8) | b[1]; };
  const r32be = (): number => {
    const b = read(4);
    return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  };
  const optional = (): Uint8Array | null => r8() === 0x01 ? read(32) : null;

  const version = r8();
  if (version !== VERSION) throw new Error(`RatchetState: unknown version 0x${version.toString(16)}`);

  const rootKey = read(32);
  const sendingChainKey = optional();
  const receivingChainKey = optional();
  const dhPriv = read(32);
  const dhPub = read(32);
  const receivingDHPublicKey = optional();
  const sendMessageCount = r32be();
  const receiveMessageCount = r32be();
  const previousSendCount = r32be();

  const skippedCount = r32be();
  const skippedMessageKeys = new Map<string, Uint8Array>();
  for (let i = 0; i < skippedCount; i++) {
    const keyLen = r16be();
    const key = dec.decode(read(keyLen));
    const mk = read(32);
    skippedMessageKeys.set(key, mk);
  }

  return {
    rootKey,
    sendingChainKey,
    receivingChainKey,
    sendingDHKey: { privateKey: dhPriv, publicKey: dhPub },
    receivingDHPublicKey,
    sendMessageCount,
    receiveMessageCount,
    previousSendCount,
    skippedMessageKeys,
  };
}

/**
 * Serialize and AES-256-GCM encrypt a RatchetState.
 *
 * Output: [12-byte nonce][AES-GCM ciphertext (includes 16-byte auth tag)]
 *
 * @param state       Ratchet state to persist
 * @param keyMaterial 32-byte AES-256 key (e.g. derived from a master key via HKDF)
 */
export async function encryptRatchetState(
  state: RatchetState,
  keyMaterial: Uint8Array
): Promise<Uint8Array> {
  const plaintext = serializeRatchetState(state);
  const { ciphertext, nonce } = await aesGCMEncrypt(keyMaterial, plaintext);
  return concat([nonce, ciphertext]);
}

/**
 * Decrypt and deserialize a RatchetState produced by encryptRatchetState().
 * Throws on authentication failure (tampered bytes) or truncated input.
 *
 * @param bytes       Output of encryptRatchetState()
 * @param keyMaterial 32-byte AES-256 key — must match the key used to encrypt
 */
export async function decryptRatchetState(
  bytes: Uint8Array,
  keyMaterial: Uint8Array
): Promise<RatchetState> {
  if (bytes.length < AES_NONCE_LEN + 1) throw new Error("RatchetState: encrypted buffer too short");
  const nonce = bytes.slice(0, AES_NONCE_LEN);
  const ciphertext = bytes.slice(AES_NONCE_LEN);
  const plaintext = await aesGCMDecrypt(keyMaterial, ciphertext, nonce);
  return deserializeRatchetState(plaintext);
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
