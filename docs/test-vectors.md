# Test Vectors — `@meshii/protocol`

Deterministic **known-answer test (KAT)** vectors and behavioral tests for the
protocol core. These pin the cryptographic composition and wire formats against
silent drift and give an independent implementation a fixed reference to check
against.

- Fixture: [`tests/vectors/protocol-core-vectors.json`](../tests/vectors/protocol-core-vectors.json)
- KAT consumer: [`tests/vectors.test.ts`](../tests/vectors.test.ts)
- Behavioral / negative-path: [`tests/behavioral.test.ts`](../tests/behavioral.test.ts)
- Test-only helper: [`tests/helpers/fixed-keys.ts`](../tests/helpers/fixed-keys.ts)

Run with `pnpm test` (the vectors run inside the normal Vitest suite). No `src/`
code, public API, build config, or existing test was modified to add them.

## Purpose

| Concern | What the vector pins |
| --- | --- |
| **Composition correctness** | X3DH DH ordering + domain separation, HKDF `info`/salt, identity-key derivation |
| **Cross-impl drift** | A second implementation must reproduce these exact bytes from the same inputs |
| **Wire-format stability** | `serializeRatchetState` byte layout (version `0x01`) and `canonicalJSON` output |
| **Signature determinism** | Ed25519 capability-token and W3C-VC signatures are byte-for-byte reproducible |
| **Standards conformance** | HMAC-SHA256 matches the RFC 4231 published digest; HKDF is reproducible per RFC 5869 |
| **Behavioral guarantees** | Out-of-order delivery, replay rejection, header/ciphertext/AAD tampering, `MAX_SKIP` bound, serialization faults |

### Anti-blind-snapshot property

The KAT test does **not** merely re-run a function and snapshot its output. For
X3DH, the routing tag, and the capability-token signature, the test **also
recomputes the expected value from first principles** using a separately written
composition (see `x3dhReceiveScratch` in `tests/vectors.test.ts` and the inline
HMAC/Ed25519 recomputations). A frozen value is therefore only accepted if two
independent code paths agree. The HMAC vector is additionally anchored to the
**RFC 4231 Test Case 2** published digest, which is independent of this codebase
entirely.

## Deterministic vs random

| Function | Deterministic? | Vector form |
| --- | --- | --- |
| `ed25519GetPublicKey`, `ed25519Sign` | ✅ (RFC 8032 §5.1.6) | frozen KAT |
| `deriveIdentityKey` (HKDF→Ed25519) | ✅ | frozen KAT |
| `x3dhReceive` | ✅ (no internal randomness) | frozen KAT |
| `computeRoutingTag` (HMAC) | ✅ | frozen KAT |
| `hkdfSHA256`, `hmacSHA256` | ✅ | frozen KAT (+RFC anchor) |
| `canonicalJSON` | ✅ | frozen KAT |
| `serializeRatchetState` | ✅ for a fixed state | frozen KAT |
| `signCapabilityToken`, `signVC` | ✅ for a fixed payload | frozen KAT |
| `x3dhSend` | ❌ generates a random ephemeral key | behavioral (send↔receive agreement) |
| `aesGCMEncrypt` / `ratchetEncrypt` | ❌ random 96-bit nonce per message | behavioral (round-trip / tamper) |
| `generateIdentityKeyBundle`, `generate*KeyPair` | ❌ CSPRNG | behavioral |

**Why some things are not frozen.** `x3dhSend` mints a fresh ephemeral X25519
key and `aesGCMEncrypt` mints a fresh 96-bit nonce on every call (both correct,
security-required behaviors). Their outputs are intentionally **not** snapshotted
— freezing a randomized output would be meaningless. They are covered instead by:

- **send↔receive agreement** — `x3dhSend` output is fed into `x3dhReceive` and the
  two shared secrets must match (the deterministic side, `x3dhReceive`, is the one
  that is frozen).
- **encrypt→decrypt round-trip + tamper rejection** for the AEAD/ratchet paths.

## How to regenerate

The expected values are produced by running the **built** code over the fixed
test inputs (the seeds in the fixture's `seeds` block). To regenerate after an
*approved* protocol change:

1. `pnpm build`
2. For each vector, call the corresponding exported function on the fixed inputs
   from `tests/vectors/protocol-core-vectors.json` and read back the hex/string
   output — e.g. `x3dhReceive(...)`, `serializeRatchetState(...)`,
   `signCapabilityToken(token, seed).signature`, `signVC(vc, seed, vm).proof.proofValue`.
   (X25519 public keys for fixed scalars use `x25519.getPublicKey` from
   `@noble/curves/ed25519`, as in `tests/helpers/fixed-keys.ts`.)
3. Update the `expected_*` fields and re-run `pnpm test`.

A regenerated value that differs from the committed one means the protocol's
observable output changed — that is a **breaking wire-format / crypto change** and
must be called out and approved explicitly (see the repo `CLAUDE.md`), not
silently re-frozen.

## Compatibility boundary

- Vectors target the protocol-core composition. **VC canonicalization is the
  project's simplified recursively-sorted-keys form, not JSON-LD URDNA2015** — the
  VC vector is reproducible by this library and any implementation that adopts the
  same canonicalization, but is **not** expected to validate under a generic
  W3C/JSON-LD verifier.
- Ed25519 / X25519 / HKDF / HMAC / AES-GCM correctness against their RFCs is
  inherited from `@noble/curves` + `@noble/hashes` (which ship their own RFC test
  suites). These vectors anchor the **Meshii composition** on top of those
  primitives, plus one direct RFC 4231 HMAC cross-check.
- `serializeRatchetState` is a Meshii-internal binary format (version `0x01`); the
  vector pins it but it is not a cross-standard format.

## Why these vectors expose no production secrets

- All key material in the fixture is **fixed low-entropy test bytes**
  (`0x11…`, `0x22…`, `Jefe`, etc.) chosen to be obviously synthetic. They are not
  derived from any wallet, SIWE session, mnemonic, seed phrase, `.env`, keystore,
  or deployed signing key.
- The DIDs/addresses are the burn placeholder
  `0x000000000000000000000000000000000000dEaD`, not a real account.
- No value in the fixture is read from the environment, a secret store, or a
  network source; everything is a literal in the committed file.
- The fixture's `_meta` block asserts `contains_secrets: false`, and the KAT test
  asserts it.
