# Signed PreKey freshness — signature v2

Hardens the Signed PreKey (SPK) against a relay serving a **stale-but-validly-
signed** SPK, by binding the SPK's metadata into a versioned, canonical
signature. Additive and backward-compatible: the legacy v1 signature is retained.

- Implementation: [`src/crypto/identity.ts`](../src/crypto/identity.ts)
- Tests: [`tests/spk-freshness.test.ts`](../tests/spk-freshness.test.ts) + the
  `spk_signature_v2` KAT in [`tests/vectors/protocol-core-vectors.json`](../tests/vectors/protocol-core-vectors.json)

## Threat model — old-but-valid SPK replay

The v1 SPK signature is `Ed25519(IK_priv, SPK_pub)` — it signs **only** the 32-byte
SPK public key. It does **not** bind the `keyId`, `createdAt`, or any expiry. A
malicious or compromised relay can therefore take a *previously valid* SPK (e.g.
one the owner has since rotated) and serve it to a sender: the v1 signature still
verifies, so the sender may run X3DH against a stale SPK. If the owner ever
retained that SPK's private key, this weakens the forward-secrecy properties of
the initial message; at minimum it removes the owner's ability to rotate away
from a given SPK.

v1 cannot distinguish a current SPK from a rotated one because nothing about
*time* or *identity of the prekey* is signed.

## v2 signature payload

The v2 signature binds the full SPK descriptor under a versioned context:

```
signatureV2 = Ed25519( IK_priv, UTF8( canonicalJSON({
  "v":         "meshii-spk-v2",
  "spk":       hex(spkPublicKey),
  "keyId":     <number>,
  "createdAt": <unix ms>,
  "expiresAt": <unix ms>     // createdAt + 7 days by default (SPK_TTL_MS)
}) ) )
```

- `canonicalJSON` is the project's existing deterministic canonicalization
  (recursively sorted keys, compact) — the same one used for VC and capability
  tokens. No new cryptographic construction is introduced.
- The context string `"meshii-spk-v2"` provides domain separation and a version
  marker for future migrations.
- Because Ed25519 signing is deterministic (RFC 8032 §5.1.6), the signature is a
  byte-exact known-answer vector (see the `spk_signature_v2` KAT).

### Verification — `verifySPKSignatureV2(bundle, { now? })`

Fail-closed. Returns `false` (never throws) when **any** of these hold:

- `signatureV2` or `expiresAt` is absent (a legacy/v1-only bundle);
- `createdAt`/`expiresAt` is non-finite, or `expiresAt <= createdAt` (malformed window);
- `now > expiresAt` (expired; `now` defaults to `Date.now()`, injectable for tests);
- the Ed25519 signature over the reconstructed canonical payload is invalid
  (catches any tampering of `spk`, `keyId`, `createdAt`, or `expiresAt`).

Returns `true` only when the signature is valid **and** the SPK is unexpired.

## Backward compatibility & migration

**Non-breaking, additive.**

- `generateIdentityKeyBundle()` now emits **both** the v1 `signature` (over
  `SPK_pub`) and the v2 `signatureV2`, plus `expiresAt`. Old consumers that read
  only the v1 fields are unaffected.
- On `IdentityKeyBundlePublic`, `signatureV2` and `expiresAt` are **optional**, so
  a bundle reconstructed from older serialized/relay data still type-checks.
- `verifySPKSignature` (v1) is unchanged and still verifies v1 signatures. It is
  marked `@deprecated`: it provides **no** freshness guarantee.
- No existing test or KAT changed; the suite grows from 124 to 140 tests (one
  new SPK-v2 KAT vector + the `tests/spk-freshness.test.ts` behavioral suite).
- `verifySPKSignatureV2`, `SPK_SIG_V2_CONTEXT`, and `SPK_TTL_MS` are exported from
  the package entry (`@meshii/protocol`) alongside the legacy `verifySPKSignature`.

There is **no forced migration**: a bundle that predates v2 (no `signatureV2`)
simply fails `verifySPKSignatureV2` (fail-closed) and must be re-published by a
client running this version to gain freshness protection.

## Operator / wrapper (PWA) guidance

To actually obtain the freshness guarantee, the consuming wrapper (PWA / relay
client) **must**:

1. **Call `verifySPKSignatureV2`** before using a fetched bundle for X3DH, and
   **treat a missing or invalid v2 signature as rejection.**
2. **Not silently fall back to `verifySPKSignature` (v1).** A downgrade to v1 re-
   exposes the old-SPK-replay risk, because a relay could strip `signatureV2` /
   `expiresAt` and serve only the v1 signature. v1 is acceptable only for an
   explicit, logged legacy-compatibility window during migration.
3. **Publish** the v2 fields (`signatureV2`, `expiresAt`) alongside the SPK so
   peers can verify freshness.
4. **Rotate** the SPK on or before `expiresAt` (default 7 days) and destroy the
   retired SPK private key, so an expired SPK cannot be used even if replayed.

## Out of scope (this change)

No change to X3DH shared-secret math, the Double Ratchet, AEAD, HKDF, identity-
key derivation, or routing-tag derivation. This change only adds SPK signature
v2 alongside v1.
