# SECURITY.md — @meshii/protocol

**Classification:** Internal | **Effective:** 2026-04-05

## Scope

This file covers the `@meshii/protocol` package only.
System-level security policy: see GAO SYSTEMS — SECURITY DOCUMENTATION SUITE.

## Cryptographic Standards

| Primitive | Algorithm | Standard | Implementation |
|-----------|-----------|----------|----------------|
| IK derivation | HKDF-SHA256 | RFC 5869 | @noble/hashes/hkdf |
| Key agreement | X25519 ECDH + X3DH | RFC 7748 | @noble/curves/ed25519 |
| Signing | Ed25519 | RFC 8032 | @noble/curves/ed25519 |
| Encryption | AES-256-GCM | NIST SP 800-38D | WebCrypto |
| MAC | HMAC-SHA256 | RFC 2104 | @noble/hashes/hmac |
| Randomness | CSPRNG | W3C Web Crypto | crypto.getRandomValues |

## Prohibited

- `Math.random()` for any cryptographic purpose
- AES in ECB or CBC mode
- Reused AES-GCM nonces
- Hardcoded keys, IVs, or salts
- GPL/LGPL/AGPL runtime dependencies (MESHINV-11)
- Native binary crypto libraries

## Vulnerability Disclosure

Do not open public GitHub issues. Contact: security@toii.ai
