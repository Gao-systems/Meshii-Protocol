import { describe, it, expect } from "vitest";
import { buildSIWEMessage, generateSIWENonce, validateSIWENonce } from "../src/siwe/index.js";
import type { SIWEMessageParams } from "../src/types/index.js";

const BASE_PARAMS: SIWEMessageParams = {
  domain: "meshii.gao",
  address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
  uri: "https://meshii.gao",
  version: "1",
  chainId: 8453,
  nonce: "abcdef1234567890",
  issuedAt: "2026-04-05T00:00:00.000Z",
};

describe("buildSIWEMessage", () => {
  it("produces valid EIP-4361 format (no statement)", () => {
    const msg = buildSIWEMessage(BASE_PARAMS);
    const lines = msg.split("\n");
    expect(lines[0]).toBe("meshii.gao wants you to sign in with your Ethereum account:");
    expect(lines[1]).toBe("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    expect(lines[2]).toBe("");
    expect(lines).toContain("URI: https://meshii.gao");
    expect(lines).toContain("Version: 1");
    expect(lines).toContain("Chain ID: 8453");
    expect(lines).toContain("Nonce: abcdef1234567890");
    expect(lines).toContain("Issued At: 2026-04-05T00:00:00.000Z");
  });

  it("includes statement with blank line after", () => {
    const msg = buildSIWEMessage({ ...BASE_PARAMS, statement: "Sign in to Meshii" });
    const lines = msg.split("\n");
    expect(lines[3]).toBe("Sign in to Meshii");
    expect(lines[4]).toBe("");
  });

  it("includes expiration time", () => {
    const msg = buildSIWEMessage({
      ...BASE_PARAMS,
      expirationTime: "2026-04-06T00:00:00.000Z",
    });
    expect(msg).toContain("Expiration Time: 2026-04-06T00:00:00.000Z");
  });

  it("includes not before", () => {
    const msg = buildSIWEMessage({ ...BASE_PARAMS, notBefore: "2026-04-05T00:00:00.000Z" });
    expect(msg).toContain("Not Before: 2026-04-05T00:00:00.000Z");
  });

  it("includes request ID", () => {
    const msg = buildSIWEMessage({ ...BASE_PARAMS, requestId: "req-123" });
    expect(msg).toContain("Request ID: req-123");
  });

  it("includes resources", () => {
    const msg = buildSIWEMessage({
      ...BASE_PARAMS,
      resources: ["https://a.com", "https://b.com"],
    });
    expect(msg).toContain("Resources:");
    expect(msg).toContain("- https://a.com");
    expect(msg).toContain("- https://b.com");
  });

  it("omits optional fields when not provided", () => {
    const msg = buildSIWEMessage(BASE_PARAMS);
    expect(msg).not.toContain("Expiration Time:");
    expect(msg).not.toContain("Not Before:");
    expect(msg).not.toContain("Request ID:");
    expect(msg).not.toContain("Resources:");
  });
});

describe("generateSIWENonce", () => {
  it("returns 32-char hex string", () => {
    const nonce = generateSIWENonce();
    expect(nonce).toHaveLength(32);
    expect(nonce).toMatch(/^[0-9a-f]{32}$/);
  });

  it("generates unique values", () => {
    const a = generateSIWENonce();
    const b = generateSIWENonce();
    expect(a).not.toBe(b);
  });

  it("passes validateSIWENonce (≥ 8 alphanumeric)", () => {
    expect(validateSIWENonce(generateSIWENonce())).toBe(true);
  });
});

describe("validateSIWENonce", () => {
  it("accepts 8+ alphanumeric chars", () => {
    expect(validateSIWENonce("abcdef12")).toBe(true);
    expect(validateSIWENonce("ABCDEF1234567890")).toBe(true);
  });

  it("rejects < 8 chars", () => {
    expect(validateSIWENonce("abc123")).toBe(false);
  });

  it("rejects special characters", () => {
    expect(validateSIWENonce("abcdef12!")).toBe(false);
    expect(validateSIWENonce("abcdef12-")).toBe(false);
  });
});
