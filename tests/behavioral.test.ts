// Behavioral / negative-path tests for the Double Ratchet and X3DH.
//
// These complement the deterministic KAT vectors (tests/vectors.test.ts) by
// exercising security-relevant behaviors that involve internal randomness and
// therefore cannot be frozen: out-of-order delivery, replay rejection, header /
// ciphertext / AAD tampering, the MAX_SKIP bound, and serialization fault
// handling. They assert behavior only — no src/ logic is modified.
import { describe, it, expect } from "vitest";
import {
  bytesToHex,
  x3dhSend,
  x3dhReceive,
  initRatchetAlice,
  initRatchetBob,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeRatchetState,
  deserializeRatchetState,
  encryptRatchetState,
  decryptRatchetState,
  generateIdentityKeyBundle,
  extractPublicBundle,
  verifySPKSignature,
  randomBytes,
} from "../src/crypto/index.js";

const te = new TextEncoder();
const td = new TextDecoder();
const enc = (s: string) => te.encode(s);
const dec = (b: Uint8Array) => td.decode(b);

// Mirrors the session bootstrap used in crypto.test.ts: X3DH (with OPK) then
// Double Ratchet init for both parties.
async function setupSession() {
  const bobBundle = generateIdentityKeyBundle(1);
  const aliceBundle = generateIdentityKeyBundle(0);
  const bobPub = extractPublicBundle(bobBundle);

  const { sharedSecret, ephemeralPublicKey } = x3dhSend(
    aliceBundle.identityKey.privateKey,
    bobPub
  );
  const bobSS = x3dhReceive(
    bobBundle.identityKey.privateKey,
    bobBundle.signedPreKey.keyPair.privateKey,
    bobBundle.oneTimePreKeys[0].keyPair.privateKey,
    aliceBundle.identityKey.publicKey,
    ephemeralPublicKey
  );

  const alice = initRatchetAlice(sharedSecret, bobBundle.signedPreKey.keyPair.publicKey);
  const bob = initRatchetBob(bobSS.sharedSecret, bobBundle.signedPreKey.keyPair);
  return { alice, bob };
}

// ---------------------------------------------------------------------------
// X3DH key agreement
// ---------------------------------------------------------------------------

describe("X3DH agreement", () => {
  it("with OPK: sender and receiver derive the same shared secret", () => {
    const alice = generateIdentityKeyBundle(0);
    const bob = generateIdentityKeyBundle(1);
    const bobPub = extractPublicBundle(bob);
    const { sharedSecret: aSS, ephemeralPublicKey } = x3dhSend(
      alice.identityKey.privateKey,
      bobPub
    );
    const { sharedSecret: bSS } = x3dhReceive(
      bob.identityKey.privateKey,
      bob.signedPreKey.keyPair.privateKey,
      bob.oneTimePreKeys[0].keyPair.privateKey,
      alice.identityKey.publicKey,
      ephemeralPublicKey
    );
    expect(bytesToHex(aSS)).toBe(bytesToHex(bSS));
  });

  it("without OPK (3DH fallback): sender and receiver still agree", () => {
    const alice = generateIdentityKeyBundle(0);
    const bob = generateIdentityKeyBundle(0);
    const bobPub = extractPublicBundle(bob);
    const { sharedSecret: aSS, ephemeralPublicKey } = x3dhSend(
      alice.identityKey.privateKey,
      bobPub
    );
    const { sharedSecret: bSS } = x3dhReceive(
      bob.identityKey.privateKey,
      bob.signedPreKey.keyPair.privateKey,
      undefined,
      alice.identityKey.publicKey,
      ephemeralPublicKey
    );
    expect(bytesToHex(aSS)).toBe(bytesToHex(bSS));
  });

  it("rejects a tampered SPK signature (caller-side verification)", () => {
    const bundle = generateIdentityKeyBundle(1);
    const pub = extractPublicBundle(bundle);
    expect(verifySPKSignature(pub)).toBe(true);
    pub.signedPreKey.signature[0] ^= 0xff;
    expect(verifySPKSignature(pub)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Double Ratchet — ordering, replay, tampering
// ---------------------------------------------------------------------------

describe("Double Ratchet ordering & integrity", () => {
  it("decrypts messages in order", async () => {
    const { alice, bob } = await setupSession();
    for (let i = 0; i < 4; i++) {
      const e = await ratchetEncrypt(alice, enc(`m${i}`));
      expect(dec(await ratchetDecrypt(bob, e))).toBe(`m${i}`);
    }
  });

  it("supports a Bob→Alice reply (DH ratchet step)", async () => {
    const { alice, bob } = await setupSession();
    const e1 = await ratchetEncrypt(alice, enc("hi bob"));
    expect(dec(await ratchetDecrypt(bob, e1))).toBe("hi bob");
    const e2 = await ratchetEncrypt(bob, enc("hi alice"));
    expect(dec(await ratchetDecrypt(alice, e2))).toBe("hi alice");
    // a second round continues to work after the DH ratchet
    const e3 = await ratchetEncrypt(alice, enc("how are you"));
    expect(dec(await ratchetDecrypt(bob, e3))).toBe("how are you");
  });

  it("decrypts out-of-order delivery via skipped keys, then drains them", async () => {
    const { alice, bob } = await setupSession();
    const e0 = await ratchetEncrypt(alice, enc("m0"));
    const e1 = await ratchetEncrypt(alice, enc("m1"));
    const e2 = await ratchetEncrypt(alice, enc("m2"));

    // Deliver newest first → 0 and 1 are stored as skipped keys
    expect(dec(await ratchetDecrypt(bob, e2))).toBe("m2");
    expect(bob.skippedMessageKeys.size).toBe(2);

    expect(dec(await ratchetDecrypt(bob, e0))).toBe("m0");
    expect(dec(await ratchetDecrypt(bob, e1))).toBe("m1");
    expect(bob.skippedMessageKeys.size).toBe(0);
  });

  it("rejects replay of an already-consumed skipped message", async () => {
    const { alice, bob } = await setupSession();
    const e0 = await ratchetEncrypt(alice, enc("m0"));
    const e1 = await ratchetEncrypt(alice, enc("m1"));
    await ratchetDecrypt(bob, e1); // m0 becomes a skipped key
    await ratchetDecrypt(bob, e0); // consume the skipped key
    await expect(ratchetDecrypt(bob, e0)).rejects.toThrow(); // replay → key gone
  });

  it("rejects replay of an in-order message", async () => {
    const { alice, bob } = await setupSession();
    const e0 = await ratchetEncrypt(alice, enc("m0"));
    expect(dec(await ratchetDecrypt(bob, e0))).toBe("m0");
    await expect(ratchetDecrypt(bob, e0)).rejects.toThrow(); // chain advanced
  });

  it("rejects a tampered header (messageCount)", async () => {
    const { alice, bob } = await setupSession();
    const e = await ratchetEncrypt(alice, enc("secret"));
    const tampered = {
      ...e,
      header: { ...e.header, messageCount: e.header.messageCount + 3 },
    };
    await expect(ratchetDecrypt(bob, tampered)).rejects.toThrow();
  });

  it("rejects a tampered header (dhPublicKey)", async () => {
    const { alice, bob } = await setupSession();
    const e = await ratchetEncrypt(alice, enc("secret"));
    const badDh = new Uint8Array(e.header.dhPublicKey);
    badDh[0] ^= 0xff;
    const tampered = { ...e, header: { ...e.header, dhPublicKey: badDh } };
    await expect(ratchetDecrypt(bob, tampered)).rejects.toThrow();
  });

  it("rejects a tampered ciphertext", async () => {
    const { alice, bob } = await setupSession();
    const e = await ratchetEncrypt(alice, enc("secret"));
    e.ciphertext[0] ^= 0xff;
    await expect(ratchetDecrypt(bob, e)).rejects.toThrow();
  });

  it("rejects mismatched associated data", async () => {
    const { alice, bob } = await setupSession();
    const e = await ratchetEncrypt(alice, enc("secret"), enc("context-A"));
    await expect(ratchetDecrypt(bob, e, enc("context-B"))).rejects.toThrow();
  });

  it("accepts matching associated data", async () => {
    const { alice, bob } = await setupSession();
    const e = await ratchetEncrypt(alice, enc("secret"), enc("context-A"));
    expect(dec(await ratchetDecrypt(bob, e, enc("context-A")))).toBe("secret");
  });
});

// ---------------------------------------------------------------------------
// MAX_SKIP bound
// ---------------------------------------------------------------------------

describe("Double Ratchet skipped-key bound (MAX_SKIP=1000)", () => {
  it("accepts a large but in-bound skip gap", async () => {
    const { alice, bob } = await setupSession();
    let last;
    for (let i = 0; i < 11; i++) {
      last = await ratchetEncrypt(alice, enc(`m${i}`));
    }
    // Deliver only the 11th → 10 skipped keys stored (well under 1000)
    expect(dec(await ratchetDecrypt(bob, last!))).toBe("m10");
    expect(bob.skippedMessageKeys.size).toBe(10);
  });

  it("rejects a skip gap greater than MAX_SKIP", async () => {
    const { alice, bob } = await setupSession();
    const e0 = await ratchetEncrypt(alice, enc("m0"));
    await ratchetDecrypt(bob, e0); // establish receiving chain
    const e1 = await ratchetEncrypt(alice, enc("m1"));
    // Craft a header that demands skipping > 1000 keys on the current chain
    const crafted = { ...e1, header: { ...e1.header, messageCount: 1002 } };
    await expect(ratchetDecrypt(bob, crafted)).rejects.toThrow(/MAX_SKIP/);
  });
});

// ---------------------------------------------------------------------------
// Serialization fault handling
// ---------------------------------------------------------------------------

describe("RatchetState serialization faults", () => {
  it("round-trips a live state and preserves the version byte", async () => {
    const { alice } = await setupSession();
    const bytes = serializeRatchetState(alice);
    expect(bytes[0]).toBe(0x01);
    const restored = deserializeRatchetState(bytes);
    expect(bytesToHex(restored.rootKey)).toBe(bytesToHex(alice.rootKey));
    expect(bytesToHex(restored.sendingChainKey!)).toBe(bytesToHex(alice.sendingChainKey!));
  });

  it("rejects an unknown version byte", async () => {
    const { alice } = await setupSession();
    const bytes = serializeRatchetState(alice);
    const bad = new Uint8Array(bytes);
    bad[0] = 0x02;
    expect(() => deserializeRatchetState(bad)).toThrow(/version/i);
  });

  it("rejects a truncated buffer", async () => {
    const { alice } = await setupSession();
    const bytes = serializeRatchetState(alice);
    expect(() => deserializeRatchetState(bytes.slice(0, 10))).toThrow(/truncated/i);
  });

  it("encryptRatchetState round-trips with the correct key", async () => {
    const { alice } = await setupSession();
    const key = randomBytes(32);
    const blob = await encryptRatchetState(alice, key);
    const restored = await decryptRatchetState(blob, key);
    expect(bytesToHex(restored.rootKey)).toBe(bytesToHex(alice.rootKey));
  });

  it("decryptRatchetState rejects the wrong key", async () => {
    const { alice } = await setupSession();
    const blob = await encryptRatchetState(alice, randomBytes(32));
    await expect(decryptRatchetState(blob, randomBytes(32))).rejects.toThrow();
  });
});
