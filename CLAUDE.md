# CLAUDE.md — @meshii/protocol

**Package:** `@meshii/protocol`
**Spec:** MESHII_PROTOCOL_SPEC_v2.1 (canonical)
**Owner:** Toii Labs LLC

## Governing Invariants

All 12 protocol invariants (MESHINV-01–12) apply. This package implements crypto primitives only — no transport, no relay, no UI.

## Crypto Rules

- `globalThis.crypto.getRandomValues` — only source of randomness
- `globalThis.crypto.subtle` — only AES-GCM implementation
- `@noble/curves` + `@noble/hashes` — only crypto libraries
- No `Math.random()`, no `Buffer`, no Node.js `crypto`, no `process.env`
- AES-256-GCM nonces: 96-bit, random per call, never reused
- Ed25519 signatures: deterministic (RFC 8032 §5.1.6)

## Forbidden

- GPL/LGPL/AGPL dependencies (MESHINV-11)
- Proprietary crypto libraries
- Hardcoded keys, IVs, or salts
- AES in ECB or CBC mode
- secp256k1 for message signing (wallet auth only)

## Before Every Task

1. Read this file
2. Read SECURITY.md
3. Run `pnpm typecheck` — zero errors required
4. Run `pnpm test` — zero failures required

## VC Issuer

Canonical issuer DID: `did:web:id.gao.domains`

## Note on VC Canonicalization

This library implements simplified Ed25519Signature2020 using deterministic JSON (sorted keys) as the signing input. Full JSON-LD RDNA canonicalization is out of scope — it requires a ~100kB processor not compatible with CF Workers zero-dep requirement.
