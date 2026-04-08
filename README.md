# @meshii/protocol

[![CI](https://github.com/Gao-systems/Meshii-Protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/Gao-systems/Meshii-Protocol/actions/workflows/ci.yml)

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
- **Identity** — IK derivation (Tier 1: HKDF-SHA256 wallet-bound; Tier 3: random Ed25519, device-local), key bundle generation, SPK signing
- **W3C VC** — `MeshiiIdentityCredential` signing and verification (Ed25519Signature2020)
- **SIWE** — EIP-4361 message construction and nonce generation (pure logic, no wallet)
- **Capability Token** — Ed25519-signed relay capability tokens (Section 9.3)
- **Routing Tag** — HMAC-SHA256 pseudonymous relay routing tags (two derivation contexts — see below)

## Identity Architecture

Meshii has two identity tiers. Both produce an Ed25519 IK keypair, a routing tag, and a prekey bundle (SPK + OPKs). They differ in how the IK is derived and bound.

### Tier 1 — Wallet-first

- IK derived via `ECDH(X25519 client ephemeral, server ephemeral) → HKDF-SHA256 → Ed25519 keypair`
- IK is bound to the user's Ethereum wallet address and a server-provided salt
- IK is held in memory only — never persisted to disk
- Routing tag: `HMAC-SHA256(IK_priv, UTF8("did:ethr:{walletAddress}") || serverSalt_bytes)`
- Full sovereign identity — recovery requires wallet re-auth

### Tier 3 — Social / Google

- IK is a randomly generated Ed25519 keypair (`generateEd25519KeyPair()`)
- IK is persisted to **IndexedDB** (`"meshii-tier3-identity"` DB, key `"device"`)
- Same device always restores the same IK — identity is continuous across logout/login
- Routing tag: `HMAC-SHA256(IK_priv, UTF8("meshii:routing:self:tier3") || IK_pub)`
- IK_pub acts as a deterministic nonce — no server salt needed
- On first login: full prekey bundle (SPK signed by IK + 100 OPKs) registered to server
- Session restored on page refresh via `/api/auth/session` cookie check + `loginSocial()` re-hydration

### Routing Tag Derivation Contexts

The two contexts are **not unified** and must not be confused:

| Tier | HMAC key | HMAC data |
|------|----------|-----------|
| Tier 1 (wallet) | `IK_priv` | `UTF8("did:ethr:{walletAddress}") \|\| serverSalt` |
| Tier 3 (social) | `IK_priv` | `UTF8("meshii:routing:self:tier3") \|\| IK_pub` |

Both return a 64-char lowercase hex string (32-byte HMAC-SHA256 output).

### Wallet Linking (additive only)

Wallet linking for an existing Tier 3 user is **purely additive metadata**. It does not:
- Replace `ikPair` or `routingTag`
- Create a new identity or orphan existing conversations

It does:
- Append the wallet address to `linkedWallets`
- Upgrade `identityProtection`: `"device-local"` → `"wallet-linked"`
- Expand `authMethods`: `["google"]` → `["google", "wallet"]`

### VC Verification Semantics

- **Tier 1:** VC verification is a hard prerequisite — failure aborts login
- **Tier 3:** VC verification is advisory only — failure logs a warning but does **not** block identity bootstrap. The IK and routing tag are anchored to the device keypair, not the VC proof.

`NEXT_PUBLIC_VC_VERIFY_KEY` must be set in the PWA environment for client-side VC verification to function.

## Dependencies

Only `@noble/curves` and `@noble/hashes` (both MIT, audited by Paul Miller).
Zero GPL/LGPL/AGPL. Zero React/Next.js/viem/wagmi.

## License

Proprietary — Toii Labs LLC. All rights reserved.
