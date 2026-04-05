import { describe, it, expect } from "vitest";
import { generateEd25519KeyPair, bytesToHex } from "../src/crypto/index.js";
import { buildVC, signVC, verifyVC, VC_ISSUER, VC_CONTEXT } from "../src/credentials/index.js";

const VM = "did:web:id.gao.domains#key-1";

describe("buildVC", () => {
  it("produces correct structure", () => {
    const vc = buildVC({
      subjectDid: "did:ethr:0x1234",
      walletAddress: "0x1234",
      identityKeyPublic: "aabbcc",
      routingTagSalt: "saltsalt",
      tier: "wallet",
    });
    expect(vc["@context"]).toEqual(VC_CONTEXT);
    expect(vc.issuer).toBe(VC_ISSUER);
    expect(vc.type).toContain("MeshiiIdentityCredential");
    expect(vc.proof).toBeUndefined();
  });

  it("sets expiry to 24h by default", () => {
    const before = Date.now();
    const vc = buildVC({
      subjectDid: "did:ethr:0x1",
      walletAddress: "0x1",
      identityKeyPublic: "aa",
      routingTagSalt: "ss",
      tier: "wallet",
    });
    const after = Date.now();
    const expiry = new Date(vc.expirationDate).getTime();
    const issuance = new Date(vc.issuanceDate).getTime();
    expect(expiry - issuance).toBeGreaterThanOrEqual(24 * 60 * 60 * 1000 - 100);
    expect(issuance).toBeGreaterThanOrEqual(before);
    expect(issuance).toBeLessThanOrEqual(after + 100);
  });

  it("includes meshiiDomain when provided", () => {
    const vc = buildVC({
      subjectDid: "did:ethr:0x1",
      walletAddress: "0x1",
      meshiiDomain: "alice.gao",
      identityKeyPublic: "aa",
      routingTagSalt: "ss",
      tier: "domain",
    });
    expect(vc.credentialSubject.meshiiDomain).toBe("alice.gao");
  });
});

describe("signVC + verifyVC", () => {
  it("sign/verify round-trip", () => {
    const kp = generateEd25519KeyPair();
    const vc = buildVC({
      subjectDid: "did:ethr:0xabc",
      walletAddress: "0xabc",
      identityKeyPublic: "deadbeef",
      routingTagSalt: "nonce123",
      tier: "wallet",
    });
    const signed = signVC(vc, kp.privateKey, VM);
    expect(signed.proof.type).toBe("Ed25519Signature2020");
    expect(signed.proof.verificationMethod).toBe(VM);
    expect(signed.proof.proofValue).toBeTruthy();
    expect(verifyVC(signed, kp.publicKey)).toBe(true);
  });

  it("verifyVC returns false with wrong key", () => {
    const kp1 = generateEd25519KeyPair();
    const kp2 = generateEd25519KeyPair();
    const vc = buildVC({
      subjectDid: "did:ethr:0x1",
      walletAddress: "0x1",
      identityKeyPublic: "aa",
      routingTagSalt: "ss",
      tier: "wallet",
    });
    const signed = signVC(vc, kp1.privateKey, VM);
    expect(verifyVC(signed, kp2.publicKey)).toBe(false);
  });

  it("verifyVC returns false when expired", () => {
    const kp = generateEd25519KeyPair();
    const vc = buildVC({
      subjectDid: "did:ethr:0x1",
      walletAddress: "0x1",
      identityKeyPublic: "aa",
      routingTagSalt: "ss",
      tier: "wallet",
      ttlMs: -1000, // already expired
    });
    const signed = signVC(vc, kp.privateKey, VM);
    expect(verifyVC(signed, kp.publicKey)).toBe(false);
  });

  it("verifyVC returns false when proof value tampered", () => {
    const kp = generateEd25519KeyPair();
    const vc = buildVC({
      subjectDid: "did:ethr:0x1",
      walletAddress: "0x1",
      identityKeyPublic: "aa",
      routingTagSalt: "ss",
      tier: "wallet",
    });
    const signed = signVC(vc, kp.privateKey, VM);
    const tampered = { ...signed, proof: { ...signed.proof, proofValue: "1111111111" } };
    expect(verifyVC(tampered, kp.publicKey)).toBe(false);
  });

  it("signing is deterministic (same key + same VC → same proofValue)", () => {
    const kp = generateEd25519KeyPair();
    const vc = buildVC({
      subjectDid: "did:ethr:0x1",
      walletAddress: "0x1",
      identityKeyPublic: "aa",
      routingTagSalt: "ss",
      tier: "wallet",
      ttlMs: 999999999,
    });
    // Fix dates so VC is identical
    const fixedVC = { ...vc, issuanceDate: "2026-01-01T00:00:00.000Z", expirationDate: "2026-01-02T00:00:00.000Z" };
    const s1 = signVC(fixedVC, kp.privateKey, VM);
    const s2 = signVC(fixedVC, kp.privateKey, VM);
    expect(s1.proof.proofValue).toBe(s2.proof.proofValue);
  });
});
