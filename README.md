# @meshii/protocol

Meshii Protocol cryptographic primitives.
Implements MESHII_PROTOCOL_SPEC_v2.1.

**Runtime targets:** Browser · Cloudflare Workers · Node.js 18+

## Install

```bash
pnpm add @meshii/protocol
```

## What's included

- **Crypto primitives** — Ed25519, X25519, HKDF-SHA256, HMAC-SHA256, AES-256-GCM
- **X3DH** — Extended Triple Diffie-Hellman key agreement (Signal spec)
- **Double Ratchet** — Forward-secret per-message encryption (Signal spec)
- **Identity** — IK derivation (client-side HKDF), key bundle generation, SPK signing
- **W3C VC** — `MeshiiIdentityCredential` signing and verification (Ed25519Signature2020)
- **SIWE** — EIP-4361 message construction and nonce generation (pure logic, no wallet)
- **Capability Token** — Ed25519-signed relay capability tokens (Section 9.3)
- **Routing Tag** — HMAC-SHA256 pseudonymous relay routing tags

## Dependencies

Only `@noble/curves` and `@noble/hashes` (both MIT, audited by Paul Miller).
Zero GPL/LGPL/AGPL. Zero React/Next.js/viem/wagmi.

## License

Proprietary — Toii Labs LLC. All rights reserved.
