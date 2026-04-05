import { describe, it, expect } from "vitest";
import { generateEd25519KeyPair } from "../src/crypto/index.js";
import {
  buildCapabilityToken,
  signCapabilityToken,
  verifyCapabilityToken,
  generateTokenNonce,
} from "../src/token/index.js";

describe("generateTokenNonce", () => {
  it("returns 32-char hex string (16 bytes)", () => {
    const n = generateTokenNonce();
    expect(n).toHaveLength(32);
    expect(n).toMatch(/^[0-9a-f]{32}$/);
  });

  it("generates unique nonces", () => {
    expect(generateTokenNonce()).not.toBe(generateTokenNonce());
  });
});

describe("buildCapabilityToken", () => {
  it("produces correct structure", () => {
    const token = buildCapabilityToken("call-uuid", "tag-hex", "caller", "did:ethr:0x1");
    expect(token.call_id).toBe("call-uuid");
    expect(token.routing_tag).toBe("tag-hex");
    expect(token.role).toBe("caller");
    expect(token.vc_subject_did).toBe("did:ethr:0x1");
    expect(token.nonce).toHaveLength(32);
    expect(token.expires_at - token.issued_at).toBe(5 * 60 * 1000);
  });

  it("clamps TTL to 5 minutes", () => {
    const token = buildCapabilityToken("c", "t", "callee", "did:ethr:0x1", 999999999);
    expect(token.expires_at - token.issued_at).toBe(5 * 60 * 1000);
  });

  it("respects shorter TTL", () => {
    const token = buildCapabilityToken("c", "t", "caller", "did:ethr:0x1", 60_000);
    expect(token.expires_at - token.issued_at).toBe(60_000);
  });
});

describe("signCapabilityToken + verifyCapabilityToken", () => {
  it("sign/verify round-trip", () => {
    const kp = generateEd25519KeyPair();
    const token = buildCapabilityToken("call-1", "tag-1", "caller", "did:ethr:0xabc");
    const signed = signCapabilityToken(token, kp.privateKey);
    expect(signed.signature).toBeTruthy();
    expect(verifyCapabilityToken(signed, kp.publicKey)).toBe(true);
  });

  it("verify fails with wrong key", () => {
    const kp1 = generateEd25519KeyPair();
    const kp2 = generateEd25519KeyPair();
    const token = buildCapabilityToken("call-1", "tag-1", "callee", "did:ethr:0xabc");
    const signed = signCapabilityToken(token, kp1.privateKey);
    expect(verifyCapabilityToken(signed, kp2.publicKey)).toBe(false);
  });

  it("verify fails when expired", () => {
    const kp = generateEd25519KeyPair();
    const token = buildCapabilityToken("call-1", "tag-1", "caller", "did:ethr:0xabc", -1000);
    const signed = signCapabilityToken(token, kp.privateKey);
    expect(verifyCapabilityToken(signed, kp.publicKey)).toBe(false);
  });

  it("verify fails with tampered signature", () => {
    const kp = generateEd25519KeyPair();
    const token = buildCapabilityToken("call-1", "tag-1", "caller", "did:ethr:0xabc");
    const signed = signCapabilityToken(token, kp.privateKey);
    const tampered = { ...signed, signature: "00".repeat(32) };
    expect(verifyCapabilityToken(tampered, kp.publicKey)).toBe(false);
  });

  it("verify fails with tampered payload field", () => {
    const kp = generateEd25519KeyPair();
    const token = buildCapabilityToken("call-1", "tag-1", "caller", "did:ethr:0xabc");
    const signed = signCapabilityToken(token, kp.privateKey);
    const tampered = { ...signed, role: "callee" as const };
    expect(verifyCapabilityToken(tampered, kp.publicKey)).toBe(false);
  });

  it("signing is deterministic", () => {
    const kp = generateEd25519KeyPair();
    const token = buildCapabilityToken("call-fixed", "tag-fixed", "caller", "did:ethr:0x1");
    const fixedToken = { ...token, issued_at: 1000, expires_at: 2000, nonce: "aabbcc" };
    const s1 = signCapabilityToken(fixedToken, kp.privateKey);
    const s2 = signCapabilityToken(fixedToken, kp.privateKey);
    expect(s1.signature).toBe(s2.signature);
  });
});
