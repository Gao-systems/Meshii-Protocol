// SPK freshness (signature v2) behavioral tests.
//
// v2 binds spkPublicKey + keyId + createdAt + expiresAt under the
// "meshii-spk-v2" context, so a relay cannot serve a stale-but-validly-signed
// SPK. These tests assert fail-closed verification, freshness/expiry handling,
// backward compatibility with v1, and that a v2-verified SPK still drives X3DH.
import { describe, it, expect } from "vitest";
import {
  bytesToHex,
  generateIdentityKeyBundle,
  extractPublicBundle,
  verifySPKSignature,
  verifySPKSignatureV2,
  x3dhSend,
  x3dhReceive,
} from "../src/crypto/index.js";

// Fresh public bundle (carries v1 signature + v2 signature + expiresAt).
function freshPublic() {
  return extractPublicBundle(generateIdentityKeyBundle(1));
}

describe("SPK signature v2 — valid path", () => {
  it("accepts a freshly generated bundle", () => {
    const pub = freshPublic();
    expect(pub.signedPreKey.signatureV2).toBeDefined();
    expect(pub.signedPreKey.expiresAt).toBeDefined();
    expect(verifySPKSignatureV2(pub)).toBe(true);
  });

  it("accepts at the exact expiry boundary (now == expiresAt) and rejects after", () => {
    const pub = freshPublic();
    const exp = pub.signedPreKey.expiresAt!;
    expect(verifySPKSignatureV2(pub, { now: exp })).toBe(true);
    expect(verifySPKSignatureV2(pub, { now: exp + 1 })).toBe(false);
  });
});

describe("SPK signature v2 — fail-closed on tampering", () => {
  it("rejects a tampered spkPublicKey", () => {
    const pub = freshPublic();
    pub.signedPreKey.publicKey[0] ^= 0xff;
    expect(verifySPKSignatureV2(pub)).toBe(false);
  });

  it("rejects a tampered keyId", () => {
    const pub = freshPublic();
    pub.signedPreKey.keyId = 999;
    expect(verifySPKSignatureV2(pub)).toBe(false);
  });

  it("rejects a tampered createdAt", () => {
    const pub = freshPublic();
    pub.signedPreKey.createdAt = pub.signedPreKey.createdAt - 1000;
    expect(verifySPKSignatureV2(pub)).toBe(false);
  });

  it("rejects a tampered expiresAt (extension attempt)", () => {
    const pub = freshPublic();
    pub.signedPreKey.expiresAt = pub.signedPreKey.expiresAt! + 10 * 365 * 24 * 60 * 60 * 1000;
    expect(verifySPKSignatureV2(pub)).toBe(false);
  });

  it("rejects a tampered v2 signature", () => {
    const pub = freshPublic();
    pub.signedPreKey.signatureV2![0] ^= 0xff;
    expect(verifySPKSignatureV2(pub)).toBe(false);
  });

  it("rejects a wrong identity key", () => {
    const pub = freshPublic();
    pub.identityKeyPublic[0] ^= 0xff;
    expect(verifySPKSignatureV2(pub)).toBe(false);
  });
});

describe("SPK signature v2 — fail-closed on missing/malformed metadata", () => {
  it("rejects when signatureV2 is absent (legacy bundle)", () => {
    const pub = freshPublic();
    delete pub.signedPreKey.signatureV2;
    expect(verifySPKSignatureV2(pub)).toBe(false);
  });

  it("rejects when expiresAt is absent", () => {
    const pub = freshPublic();
    delete pub.signedPreKey.expiresAt;
    expect(verifySPKSignatureV2(pub)).toBe(false);
  });

  it("rejects a malformed validity window (expiresAt <= createdAt)", () => {
    const pub = freshPublic();
    pub.signedPreKey.expiresAt = pub.signedPreKey.createdAt - 1;
    expect(verifySPKSignatureV2(pub)).toBe(false);
  });

  it("rejects a non-finite `now` (NaN / ±Infinity)", () => {
    const pub = freshPublic();
    expect(verifySPKSignatureV2(pub, { now: NaN })).toBe(false);
    expect(verifySPKSignatureV2(pub, { now: -Infinity })).toBe(false);
    expect(verifySPKSignatureV2(pub, { now: Infinity })).toBe(false);
  });
});

describe("SPK signature — backward compatibility", () => {
  it("v1 verifySPKSignature still accepts the bundle (legacy path intact)", () => {
    const pub = freshPublic();
    expect(verifySPKSignature(pub)).toBe(true);
  });

  it("v1 verifySPKSignature rejects a tampered SPK public key", () => {
    const pub = freshPublic();
    pub.signedPreKey.publicKey[0] ^= 0xff;
    expect(verifySPKSignature(pub)).toBe(false);
  });
});

describe("SPK signature v2 — X3DH still agrees after verification", () => {
  it("a v2-verified SPK drives a matching X3DH shared secret", () => {
    const alice = generateIdentityKeyBundle(0);
    const bob = generateIdentityKeyBundle(1);
    const bobPub = extractPublicBundle(bob);

    expect(verifySPKSignatureV2(bobPub)).toBe(true);

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
});
