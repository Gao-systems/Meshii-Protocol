# CLAUDE.md — Meshii Protocol

## MANDATORY: Read this file before any action.

### Rules

1. Before making any code or config change, first show a concise diff plan and wait for explicit approval.
1. Any modification to `src/`, `tests/`, `package.json`, lockfiles, CI, build config, or tsconfig MUST be explicitly listed in the diff plan and approved before execution.
1. Do not add runtime or dev dependencies without listing them first and waiting for approval.
1. Do not remove or relax security checks, validation, or test assertions to make builds pass.
1. No `Math.random()`, `Date.now()` for entropy, no `Buffer`, no Node.js `crypto`, and no `process.env` usage inside `src/`.
1. Preserve backward compatibility for all public exports; flag breaking changes explicitly before editing.
1. If a referenced file/path does not exist, report it and stop. Do not invent replacements without approval.
1. After any approved code change, run `pnpm typecheck && pnpm test` and report results.
- All existing tests must pass
- Test coverage and count must not regress from the current baseline unless explicitly approved
1. Commit messages must follow: `type(scope): description`
1. Do not bypass failing tests by:
- modifying test expectations without justification
- disabling/skipping tests
- altering test config (Vitest, tsconfig, CI) without explicit approval
1. Do not change cryptographic primitives, encoding formats, or protocol logic (canonicalJSON, signatures, ratchet state, key derivation) without explicit approval and justification.
1. All code must remain compatible with Browser, Cloudflare Workers, and Node 18+.
   Do not introduce environment-specific APIs into shared code.
1. All encoding/decoding must be deterministic and protocol-safe:
- Use canonical JSON where required
- Do not change serialization formats (JSON shape, base64/base64url, byte encoding) without explicit approval
1. If unsure about any change affecting security, crypto, or protocol behavior:
- STOP
- Explain the uncertainty
- Ask for clarification before proceeding

### Stack

- Runtime: Browser + Cloudflare Workers + Node 18+
- Crypto: `@noble/curves` + `@noble/hashes` only
- Test: Vitest 2.x — baseline 91/91
- CI: GitHub Actions (Node 18.x + 20.x matrix)

### Key files

- `src/crypto/primitives.ts` — canonicalJSON + crypto primitives
- `src/crypto/double-ratchet.ts` — X3DH + Double Ratchet + RatchetState serialization
- `src/credentials/vc.ts` — W3C VC issuance + verification
- `src/token/capability.ts` — capability token sign + verify
- `tests/setup.ts` — WebCrypto polyfill for Vitest
