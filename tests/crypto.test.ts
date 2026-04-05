import { describe, it, expect } from "vitest";
import {
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
  x3dhSend,
  x3dhReceive,
  initRatchetAlice,
  initRatchetBob,
  ratchetEncrypt,
  ratchetDecrypt,
  deriveIdentityKey,
  generateIdentityKeyBundle,
  extractPublicBundle,
  verifySPKSignature,
  computeRoutingTag,
  generateRoutingTagNonce,
} from "../src/crypto/index.js";

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

describe("randomBytes", () => {
  it("returns correct length", () => {
    expect(randomBytes(16)).toHaveLength(16);
    expect(randomBytes(32)).toHaveLength(32);
  });
  it("generates different values each call", () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });
});

describe("Ed25519", () => {
  it("generateEd25519KeyPair returns 32-byte keys", () => {
    const kp = generateEd25519KeyPair();
    expect(kp.privateKey).toHaveLength(32);
    expect(kp.publicKey).toHaveLength(32);
  });

  it("ed25519GetPublicKey is deterministic", () => {
    const kp = generateEd25519KeyPair();
    const pub2 = ed25519GetPublicKey(kp.privateKey);
    expect(bytesToHex(pub2)).toBe(bytesToHex(kp.publicKey));
  });

  it("sign and verify round-trip", () => {
    const kp = generateEd25519KeyPair();
    const msg = new TextEncoder().encode("meshii-test");
    const sig = ed25519Sign(kp.privateKey, msg);
    expect(ed25519Verify(kp.publicKey, msg, sig)).toBe(true);
  });

  it("verify rejects wrong message", () => {
    const kp = generateEd25519KeyPair();
    const sig = ed25519Sign(kp.privateKey, new TextEncoder().encode("hello"));
    expect(ed25519Verify(kp.publicKey, new TextEncoder().encode("world"), sig)).toBe(false);
  });

  it("verify rejects wrong key", () => {
    const kp1 = generateEd25519KeyPair();
    const kp2 = generateEd25519KeyPair();
    const msg = new TextEncoder().encode("test");
    const sig = ed25519Sign(kp1.privateKey, msg);
    expect(ed25519Verify(kp2.publicKey, msg, sig)).toBe(false);
  });

  it("verify returns false (not throws) on garbage signature", () => {
    const kp = generateEd25519KeyPair();
    const msg = new TextEncoder().encode("test");
    const badSig = randomBytes(64);
    expect(() => ed25519Verify(kp.publicKey, msg, badSig)).not.toThrow();
    expect(ed25519Verify(kp.publicKey, msg, badSig)).toBe(false);
  });
});

describe("X25519", () => {
  it("generateX25519KeyPair returns 32-byte keys", () => {
    const kp = generateX25519KeyPair();
    expect(kp.privateKey).toHaveLength(32);
    expect(kp.publicKey).toHaveLength(32);
  });

  it("DH is symmetric: DH(a_priv, b_pub) === DH(b_priv, a_pub)", () => {
    const a = generateX25519KeyPair();
    const b = generateX25519KeyPair();
    const ab = x25519DH(a.privateKey, b.publicKey);
    const ba = x25519DH(b.privateKey, a.publicKey);
    expect(bytesToHex(ab)).toBe(bytesToHex(ba));
  });
});

describe("Ed25519 ↔ X25519 conversion", () => {
  it("ed25519PubToX25519 returns 32 bytes", () => {
    const kp = generateEd25519KeyPair();
    const x = ed25519PubToX25519(kp.publicKey);
    expect(x).toHaveLength(32);
  });

  it("ed25519PrivToX25519 returns 32 bytes", () => {
    const kp = generateEd25519KeyPair();
    const x = ed25519PrivToX25519(kp.privateKey);
    expect(x).toHaveLength(32);
  });
});

describe("hkdfSHA256", () => {
  it("returns correct length", () => {
    const out = hkdfSHA256(randomBytes(32), randomBytes(32), "test", 32);
    expect(out).toHaveLength(32);
  });

  it("is deterministic", () => {
    const ikm = randomBytes(32);
    const salt = randomBytes(32);
    const a = hkdfSHA256(ikm, salt, "meshii-test", 32);
    const b = hkdfSHA256(ikm, salt, "meshii-test", 32);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  it("different info produces different output", () => {
    const ikm = randomBytes(32);
    const salt = randomBytes(32);
    const a = hkdfSHA256(ikm, salt, "info-a", 32);
    const b = hkdfSHA256(ikm, salt, "info-b", 32);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });
});

describe("hmacSHA256", () => {
  it("returns 32 bytes", () => {
    expect(hmacSHA256(randomBytes(32), randomBytes(32))).toHaveLength(32);
  });

  it("is deterministic", () => {
    const key = randomBytes(32);
    const data = new TextEncoder().encode("test");
    const a = hmacSHA256(key, data);
    const b = hmacSHA256(key, data);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });
});

describe("AES-256-GCM", () => {
  it("encrypt/decrypt round-trip", async () => {
    const key = randomBytes(32);
    const plaintext = new TextEncoder().encode("hello meshii");
    const { ciphertext, nonce } = await aesGCMEncrypt(key, plaintext);
    const decrypted = await aesGCMDecrypt(key, ciphertext, nonce);
    expect(new TextDecoder().decode(decrypted)).toBe("hello meshii");
  });

  it("round-trip with AAD", async () => {
    const key = randomBytes(32);
    const pt = new TextEncoder().encode("secret");
    const aad = new TextEncoder().encode("associated");
    const { ciphertext, nonce } = await aesGCMEncrypt(key, pt, aad);
    const dec = await aesGCMDecrypt(key, ciphertext, nonce, aad);
    expect(new TextDecoder().decode(dec)).toBe("secret");
  });

  it("generates unique nonces", async () => {
    const key = randomBytes(32);
    const pt = new TextEncoder().encode("test");
    const a = await aesGCMEncrypt(key, pt);
    const b = await aesGCMEncrypt(key, pt);
    expect(bytesToHex(a.nonce)).not.toBe(bytesToHex(b.nonce));
  });

  it("decrypt fails with wrong key", async () => {
    const key1 = randomBytes(32);
    const key2 = randomBytes(32);
    const pt = new TextEncoder().encode("test");
    const { ciphertext, nonce } = await aesGCMEncrypt(key1, pt);
    await expect(aesGCMDecrypt(key2, ciphertext, nonce)).rejects.toThrow();
  });

  it("decrypt fails with wrong AAD", async () => {
    const key = randomBytes(32);
    const pt = new TextEncoder().encode("test");
    const aad1 = new TextEncoder().encode("aad-a");
    const aad2 = new TextEncoder().encode("aad-b");
    const { ciphertext, nonce } = await aesGCMEncrypt(key, pt, aad1);
    await expect(aesGCMDecrypt(key, ciphertext, nonce, aad2)).rejects.toThrow();
  });
});

describe("base58", () => {
  it("encode/decode round-trip", () => {
    const bytes = randomBytes(64);
    expect(bytesToHex(decodeBase58(encodeBase58(bytes)))).toBe(bytesToHex(bytes));
  });

  it("handles leading zero bytes", () => {
    const bytes = new Uint8Array([0, 0, 1, 2, 3]);
    const encoded = encodeBase58(bytes);
    const decoded = decodeBase58(encoded);
    expect(bytesToHex(decoded)).toBe(bytesToHex(bytes));
  });

  it("throws on invalid character", () => {
    expect(() => decodeBase58("0invalid")).toThrow();
  });
});

describe("concat", () => {
  it("concatenates arrays", () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4]);
    expect(concat([a, b])).toEqual(new Uint8Array([1, 2, 3, 4]));
  });
});

describe("uint32ToBytes", () => {
  it("encodes big-endian", () => {
    const b = uint32ToBytes(256);
    expect(b).toEqual(new Uint8Array([0, 0, 1, 0]));
  });
});

describe("bytesEqual", () => {
  it("returns true for equal arrays", () => {
    const a = new Uint8Array([1, 2, 3]);
    expect(bytesEqual(a, new Uint8Array([1, 2, 3]))).toBe(true);
  });
  it("returns false for different arrays", () => {
    expect(bytesEqual(new Uint8Array([1]), new Uint8Array([2]))).toBe(false);
  });
  it("returns false for different lengths", () => {
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1]))).toBe(false);
  });
});

describe("bytesToHex / hexToBytes", () => {
  it("round-trip", () => {
    const b = randomBytes(16);
    expect(bytesToHex(hexToBytes(bytesToHex(b)))).toBe(bytesToHex(b));
  });
});

// ---------------------------------------------------------------------------
// X3DH
// ---------------------------------------------------------------------------

describe("X3DH", () => {
  it("sender and receiver derive the same shared secret (with OPK)", () => {
    const aliceBundle = generateIdentityKeyBundle(1);
    const bobBundle = generateIdentityKeyBundle(1);
    const bobPub = extractPublicBundle(bobBundle);

    const { sharedSecret: aliceSS, ephemeralPublicKey: aliceEK } = x3dhSend(
      aliceBundle.identityKey.privateKey,
      bobPub
    );

    const { sharedSecret: bobSS } = x3dhReceive(
      bobBundle.identityKey.privateKey,
      bobBundle.signedPreKey.keyPair.privateKey,
      bobBundle.oneTimePreKeys[0].keyPair.privateKey,
      aliceBundle.identityKey.publicKey,
      aliceEK
    );

    expect(bytesToHex(aliceSS)).toBe(bytesToHex(bobSS));
  });

  it("sender and receiver derive the same shared secret (without OPK)", () => {
    const aliceBundle = generateIdentityKeyBundle(0);
    const bobBundle = generateIdentityKeyBundle(0);
    const bobPub = extractPublicBundle(bobBundle);

    const { sharedSecret: aliceSS, ephemeralPublicKey: aliceEK } = x3dhSend(
      aliceBundle.identityKey.privateKey,
      bobPub
    );

    const { sharedSecret: bobSS } = x3dhReceive(
      bobBundle.identityKey.privateKey,
      bobBundle.signedPreKey.keyPair.privateKey,
      undefined,
      aliceBundle.identityKey.publicKey,
      aliceEK
    );

    expect(bytesToHex(aliceSS)).toBe(bytesToHex(bobSS));
  });

  it("different sessions produce different shared secrets", () => {
    const alice = generateIdentityKeyBundle(0);
    const bob = generateIdentityKeyBundle(0);
    const bobPub = extractPublicBundle(bob);
    const r1 = x3dhSend(alice.identityKey.privateKey, bobPub);
    const r2 = x3dhSend(alice.identityKey.privateKey, bobPub);
    expect(bytesToHex(r1.sharedSecret)).not.toBe(bytesToHex(r2.sharedSecret));
  });
});

// ---------------------------------------------------------------------------
// Double Ratchet
// ---------------------------------------------------------------------------

describe("Double Ratchet", () => {
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

  it("Alice→Bob round-trip", async () => {
    const { alice, bob } = await setupSession();
    const pt = new TextEncoder().encode("hello bob");
    const enc = await ratchetEncrypt(alice, pt);
    const dec = await ratchetDecrypt(bob, enc);
    expect(new TextDecoder().decode(dec)).toBe("hello bob");
  });

  it("Bob→Alice round-trip after Alice→Bob", async () => {
    const { alice, bob } = await setupSession();
    const enc1 = await ratchetEncrypt(alice, new TextEncoder().encode("hello"));
    await ratchetDecrypt(bob, enc1);
    const enc2 = await ratchetEncrypt(bob, new TextEncoder().encode("reply"));
    const dec = await ratchetDecrypt(alice, enc2);
    expect(new TextDecoder().decode(dec)).toBe("reply");
  });

  it("multiple messages in sequence", async () => {
    const { alice, bob } = await setupSession();
    for (let i = 0; i < 5; i++) {
      const msg = `message ${i}`;
      const enc = await ratchetEncrypt(alice, new TextEncoder().encode(msg));
      const dec = await ratchetDecrypt(bob, enc);
      expect(new TextDecoder().decode(dec)).toBe(msg);
    }
  });

  it("decrypt fails with tampered ciphertext", async () => {
    const { alice, bob } = await setupSession();
    const enc = await ratchetEncrypt(alice, new TextEncoder().encode("secret"));
    enc.ciphertext[0] ^= 0xff; // tamper
    await expect(ratchetDecrypt(bob, enc)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

describe("deriveIdentityKey", () => {
  it("is deterministic from same inputs", () => {
    const ss = randomBytes(32);
    const nonce = randomBytes(16);
    const ik1 = deriveIdentityKey(ss, "alice.gao", nonce);
    const ik2 = deriveIdentityKey(ss, "alice.gao", nonce);
    expect(bytesToHex(ik1.publicKey)).toBe(bytesToHex(ik2.publicKey));
  });

  it("different domain produces different key", () => {
    const ss = randomBytes(32);
    const nonce = randomBytes(16);
    const ik1 = deriveIdentityKey(ss, "alice.gao", nonce);
    const ik2 = deriveIdentityKey(ss, "bob.gao", nonce);
    expect(bytesToHex(ik1.publicKey)).not.toBe(bytesToHex(ik2.publicKey));
  });

  it("different nonce produces different key", () => {
    const ss = randomBytes(32);
    const ik1 = deriveIdentityKey(ss, "alice.gao", randomBytes(16));
    const ik2 = deriveIdentityKey(ss, "alice.gao", randomBytes(16));
    expect(bytesToHex(ik1.publicKey)).not.toBe(bytesToHex(ik2.publicKey));
  });

  it("returns valid Ed25519 keys (public key is 32 bytes)", () => {
    const ik = deriveIdentityKey(randomBytes(32), "test.gao", randomBytes(16));
    expect(ik.privateKey).toHaveLength(32);
    expect(ik.publicKey).toHaveLength(32);
    // Verify public key is consistent with private key
    const pub2 = ed25519GetPublicKey(ik.privateKey);
    expect(bytesToHex(pub2)).toBe(bytesToHex(ik.publicKey));
  });
});

describe("generateIdentityKeyBundle", () => {
  it("generates correct structure", () => {
    const bundle = generateIdentityKeyBundle(5);
    expect(bundle.identityKey.privateKey).toHaveLength(32);
    expect(bundle.identityKey.publicKey).toHaveLength(32);
    expect(bundle.signedPreKey.keyPair.publicKey).toHaveLength(32);
    expect(bundle.signedPreKey.signature).toHaveLength(64);
    expect(bundle.oneTimePreKeys).toHaveLength(5);
  });

  it("SPK signature is valid", () => {
    const bundle = generateIdentityKeyBundle(1);
    expect(
      ed25519Verify(
        bundle.identityKey.publicKey,
        bundle.signedPreKey.keyPair.publicKey,
        bundle.signedPreKey.signature
      )
    ).toBe(true);
  });

  it("defaults to 100 OPKs", () => {
    const bundle = generateIdentityKeyBundle();
    expect(bundle.oneTimePreKeys).toHaveLength(100);
  });
});

describe("extractPublicBundle + verifySPKSignature", () => {
  it("extracts correct public data", () => {
    const bundle = generateIdentityKeyBundle(2);
    const pub = extractPublicBundle(bundle);
    expect(bytesToHex(pub.identityKeyPublic)).toBe(
      bytesToHex(bundle.identityKey.publicKey)
    );
    expect(pub.oneTimePreKeys).toHaveLength(2);
  });

  it("verifySPKSignature returns true on valid bundle", () => {
    const bundle = generateIdentityKeyBundle(1);
    expect(verifySPKSignature(extractPublicBundle(bundle))).toBe(true);
  });

  it("verifySPKSignature returns false on tampered SPK", () => {
    const bundle = generateIdentityKeyBundle(1);
    const pub = extractPublicBundle(bundle);
    pub.signedPreKey.publicKey[0] ^= 0xff;
    expect(verifySPKSignature(pub)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

describe("computeRoutingTag", () => {
  it("is deterministic", () => {
    const ik = generateEd25519KeyPair();
    const nonce = generateRoutingTagNonce();
    const t1 = computeRoutingTag(ik.privateKey, "did:ethr:0xabc", nonce);
    const t2 = computeRoutingTag(ik.privateKey, "did:ethr:0xabc", nonce);
    expect(t1).toBe(t2);
  });

  it("different recipient produces different tag", () => {
    const ik = generateEd25519KeyPair();
    const nonce = generateRoutingTagNonce();
    const t1 = computeRoutingTag(ik.privateKey, "did:ethr:0xaaa", nonce);
    const t2 = computeRoutingTag(ik.privateKey, "did:ethr:0xbbb", nonce);
    expect(t1).not.toBe(t2);
  });

  it("different nonce produces different tag", () => {
    const ik = generateEd25519KeyPair();
    const t1 = computeRoutingTag(ik.privateKey, "did:ethr:0xabc", generateRoutingTagNonce());
    const t2 = computeRoutingTag(ik.privateKey, "did:ethr:0xabc", generateRoutingTagNonce());
    expect(t1).not.toBe(t2);
  });

  it("returns 64-char hex string (32 bytes)", () => {
    const ik = generateEd25519KeyPair();
    const tag = computeRoutingTag(ik.privateKey, "test", generateRoutingTagNonce());
    expect(tag).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("generateRoutingTagNonce", () => {
  it("returns 16 bytes", () => {
    expect(generateRoutingTagNonce()).toHaveLength(16);
  });
});
