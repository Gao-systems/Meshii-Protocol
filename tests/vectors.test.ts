import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import {
  ed25519GetPublicKey,
  ed25519Sign,
  hkdfSHA256,
  hmacSHA256,
  x25519DH,
  ed25519PubToX25519,
  ed25519PrivToX25519,
  concat,
  bytesToHex,
  hexToBytes,
  x3dhReceive,
  deriveIdentityKey,
  computeRoutingTag,
  serializeRatchetState,
  deserializeRatchetState,
  verifySPKSignatureV2,
} from "../src/crypto/index.js";
import { canonicalJSON } from "../src/crypto/primitives.js";
import { signCapabilityToken, verifyCapabilityToken } from "../src/token/index.js";
import { signVC, verifyVC, VC_ISSUER, VC_CONTEXT } from "../src/credentials/index.js";
import {
  x25519PublicFromScalar,
  X3DH_F_BYTES,
  X3DH_ZERO_SALT,
  X3DH_INFO,
} from "./helpers/fixed-keys.js";

// Load the known-answer test (KAT) fixture. Tests run the shipped functions on
// the fixed inputs and assert the frozen outputs, so any drift in the protocol
// composition or wire format breaks the build.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const V: any = JSON.parse(
  readFileSync(new URL("./vectors/protocol-core-vectors.json", import.meta.url), "utf8")
);
const h = hexToBytes;
const te = new TextEncoder();

describe("KAT: fixture integrity", () => {
  it("fixture declares it is deterministic and secret-free", () => {
    expect(V._meta.deterministic).toBe(true);
    expect(V._meta.contains_secrets).toBe(false);
  });
});

describe("KAT: identity public keys (Ed25519 deterministic)", () => {
  it("alice/bob IK public keys match", () => {
    expect(bytesToHex(ed25519GetPublicKey(h(V.seeds.alice_ik_seed_ed25519)))).toBe(
      V.identity_pubkeys.alice_ik_public
    );
    expect(bytesToHex(ed25519GetPublicKey(h(V.seeds.bob_ik_seed_ed25519)))).toBe(
      V.identity_pubkeys.bob_ik_public
    );
  });

  it("X25519 public keys from fixed scalars match", () => {
    expect(bytesToHex(x25519PublicFromScalar(h(V.seeds.alice_ek_scalar_x25519)))).toBe(
      V.identity_pubkeys.alice_ek_public
    );
    expect(bytesToHex(x25519PublicFromScalar(h(V.seeds.bob_spk_scalar_x25519)))).toBe(
      V.identity_pubkeys.bob_spk_public
    );
    expect(bytesToHex(x25519PublicFromScalar(h(V.seeds.bob_opk_scalar_x25519)))).toBe(
      V.identity_pubkeys.bob_opk_public
    );
  });
});

describe("KAT: deriveIdentityKey", () => {
  it("derives the frozen IK from fixed shared secret + domain + nonce", () => {
    const d = V.derive_identity_key;
    const ik = deriveIdentityKey(h(d.shared_secret), d.domain, h(d.nonce));
    expect(bytesToHex(ik.privateKey)).toBe(d.expected_private);
    expect(bytesToHex(ik.publicKey)).toBe(d.expected_public);
    // public key must be the Ed25519 public of the derived seed
    expect(bytesToHex(ed25519GetPublicKey(ik.privateKey))).toBe(d.expected_public);
  });
});

// Independent, from-first-principles X3DH receiver recomputation. Mirrors
// src/crypto/x3dh.ts but is written separately here, so a frozen value can
// never be a blind snapshot of a buggy composition.
function x3dhReceiveScratch(
  ikPriv: Uint8Array,
  spkPriv: Uint8Array,
  opkPriv: Uint8Array | undefined,
  senderIKPub: Uint8Array,
  senderEKPub: Uint8Array
): Uint8Array {
  const ikAx = ed25519PubToX25519(senderIKPub);
  const ikBx = ed25519PrivToX25519(ikPriv);
  const dh1 = x25519DH(spkPriv, ikAx);
  const dh2 = x25519DH(ikBx, senderEKPub);
  const dh3 = x25519DH(spkPriv, senderEKPub);
  const ikm =
    opkPriv !== undefined
      ? concat([X3DH_F_BYTES, dh1, dh2, dh3, x25519DH(opkPriv, senderEKPub)])
      : concat([X3DH_F_BYTES, dh1, dh2, dh3]);
  return hkdfSHA256(ikm, X3DH_ZERO_SALT, X3DH_INFO, 32);
}

describe("KAT: X3DH shared secret (deterministic receiver)", () => {
  it("with OPK: x3dhReceive matches frozen value AND independent recomputation", () => {
    const senderIK = ed25519GetPublicKey(h(V.seeds.alice_ik_seed_ed25519));
    const senderEK = x25519PublicFromScalar(h(V.seeds.alice_ek_scalar_x25519));
    expect(bytesToHex(senderIK)).toBe(V.x3dh.sender_ik_public);
    expect(bytesToHex(senderEK)).toBe(V.x3dh.sender_ek_public);

    const ss = x3dhReceive(
      h(V.x3dh.recipient_ik_seed),
      h(V.x3dh.recipient_spk_scalar),
      h(V.x3dh.recipient_opk_scalar),
      senderIK,
      senderEK
    ).sharedSecret;
    expect(bytesToHex(ss)).toBe(V.x3dh.expected_shared_secret_with_opk);

    const scratch = x3dhReceiveScratch(
      h(V.x3dh.recipient_ik_seed),
      h(V.x3dh.recipient_spk_scalar),
      h(V.x3dh.recipient_opk_scalar),
      senderIK,
      senderEK
    );
    expect(bytesToHex(scratch)).toBe(V.x3dh.expected_shared_secret_with_opk);
  });

  it("without OPK (3DH fallback): matches frozen value AND independent recomputation", () => {
    const senderIK = ed25519GetPublicKey(h(V.seeds.alice_ik_seed_ed25519));
    const senderEK = x25519PublicFromScalar(h(V.seeds.alice_ek_scalar_x25519));

    const ss = x3dhReceive(
      h(V.x3dh.recipient_ik_seed),
      h(V.x3dh.recipient_spk_scalar),
      undefined,
      senderIK,
      senderEK
    ).sharedSecret;
    expect(bytesToHex(ss)).toBe(V.x3dh.expected_shared_secret_without_opk);

    const scratch = x3dhReceiveScratch(
      h(V.x3dh.recipient_ik_seed),
      h(V.x3dh.recipient_spk_scalar),
      undefined,
      senderIK,
      senderEK
    );
    expect(bytesToHex(scratch)).toBe(V.x3dh.expected_shared_secret_without_opk);

    // with-OPK and without-OPK must differ (DH4 contributes)
    expect(V.x3dh.expected_shared_secret_with_opk).not.toBe(
      V.x3dh.expected_shared_secret_without_opk
    );
  });
});

describe("KAT: routing tag", () => {
  it("matches frozen value AND independent HMAC recomputation", () => {
    const r = V.routing_tag;
    const tag = computeRoutingTag(h(r.ik_private), r.recipient_id, h(r.nonce));
    expect(tag).toBe(r.expected_tag);

    const scratch = bytesToHex(
      hmacSHA256(h(r.ik_private), concat([te.encode(r.recipient_id), h(r.nonce)]))
    );
    expect(scratch).toBe(r.expected_tag);
  });
});

describe("KAT: HKDF-SHA256 (reproducible by any RFC 5869 impl)", () => {
  it("matches frozen OKM", () => {
    const k = V.hkdf;
    expect(bytesToHex(hkdfSHA256(h(k.ikm), h(k.salt), k.info_utf8, k.length))).toBe(
      k.expected_okm
    );
  });
});

describe("KAT: HMAC-SHA256 external anchor (RFC 4231 Test Case 2)", () => {
  it("@noble HMAC-SHA256 equals the RFC-published digest", () => {
    const m = V.hmac_rfc4231_tc2;
    expect(bytesToHex(hmacSHA256(te.encode(m.key_utf8), te.encode(m.data_utf8)))).toBe(
      m.expected_hmac
    );
  });
});

describe("KAT: canonicalJSON", () => {
  it("produces the frozen canonical string", () => {
    expect(canonicalJSON(V.canonical_json.input)).toBe(V.canonical_json.expected);
  });
});

describe("KAT: RatchetState serialization wire format", () => {
  it("serializes fixed state to the frozen bytes and round-trips", () => {
    const s = V.ratchet_state_serialization;
    const state = {
      rootKey: h(s.root_key),
      sendingChainKey: s.sending_chain_key === null ? null : h(s.sending_chain_key),
      receivingChainKey: s.receiving_chain_key === null ? null : h(s.receiving_chain_key),
      sendingDHKey: {
        privateKey: h(s.sending_dh_private),
        publicKey: h(s.sending_dh_public),
      },
      receivingDHPublicKey: s.receiving_dh_public === null ? null : h(s.receiving_dh_public),
      sendMessageCount: s.send_message_count,
      receiveMessageCount: s.receive_message_count,
      previousSendCount: s.previous_send_count,
      skippedMessageKeys: new Map<string, Uint8Array>([
        [s.skipped_key, h(s.skipped_message_key)],
      ]),
    };
    const bytes = serializeRatchetState(state);
    expect(bytes[0]).toBe(0x01); // version
    expect(bytesToHex(bytes)).toBe(s.expected_serialized);

    const restored = deserializeRatchetState(bytes);
    expect(bytesToHex(restored.rootKey)).toBe(s.root_key);
    expect(restored.receivingChainKey).toBeNull();
    expect(restored.sendMessageCount).toBe(s.send_message_count);
    expect(restored.receiveMessageCount).toBe(s.receive_message_count);
    expect(restored.previousSendCount).toBe(s.previous_send_count);
    expect(restored.skippedMessageKeys.size).toBe(1);
    expect(bytesToHex(restored.skippedMessageKeys.get(s.skipped_key)!)).toBe(
      s.skipped_message_key
    );
  });
});

describe("KAT: capability token (Ed25519 deterministic signing)", () => {
  it("canonical JSON + signature match frozen, verify true, independent recompute", () => {
    const c = V.capability_token;
    expect(canonicalJSON(c.token)).toBe(c.expected_canonical_json);

    const signed = signCapabilityToken(c.token, h(c.signing_seed));
    expect(signed.signature).toBe(c.expected_signature);

    const verifyPub = ed25519GetPublicKey(h(c.signing_seed));
    expect(bytesToHex(verifyPub)).toBe(c.verify_public);
    expect(verifyCapabilityToken(signed, verifyPub)).toBe(true);

    // independent: signature == Ed25519Sign(seed, UTF8(canonicalJSON(token)))
    const scratch = bytesToHex(ed25519Sign(h(c.signing_seed), te.encode(c.expected_canonical_json)));
    expect(scratch).toBe(c.expected_signature);
  });
});

describe("KAT: W3C VC (Ed25519Signature2020 deterministic)", () => {
  it("proofValue matches frozen value and verifies true", () => {
    const v = V.vc;
    const vc = {
      "@context": VC_CONTEXT,
      type: ["VerifiableCredential", "MeshiiIdentityCredential"],
      issuer: VC_ISSUER,
      issuanceDate: v.credential.issuanceDate,
      expirationDate: v.credential.expirationDate,
      credentialSubject: v.credential.credentialSubject,
    };
    const signed = signVC(vc, h(v.signing_seed), v.verification_method);
    expect(signed.proof.proofValue).toBe(v.expected_proof_value);

    const verifyPub = ed25519GetPublicKey(h(v.signing_seed));
    expect(bytesToHex(verifyPub)).toBe(v.verify_public);
    expect(verifyVC(signed, verifyPub)).toBe(true);
  });
});

describe("KAT: SPK signature v2 (Ed25519 deterministic, freshness-bound)", () => {
  it("signature matches frozen value, verifies true, independent recompute", () => {
    const s = V.spk_signature_v2;
    // independent recompute: sig == Ed25519Sign(IK_seed, UTF8(canonicalJSON(payload)))
    const payload = canonicalJSON({
      v: s.context,
      spk: s.spk_public,
      keyId: s.keyId,
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
    });
    expect(payload).toBe(s.expected_canonical_payload);
    expect(bytesToHex(ed25519Sign(h(s.ik_seed), new TextEncoder().encode(payload)))).toBe(
      s.expected_signature_v2
    );

    // library verifier accepts a public bundle carrying the frozen v2 signature
    const bundle = {
      identityKeyPublic: h(s.ik_public),
      signedPreKey: {
        publicKey: h(s.spk_public),
        signature: new Uint8Array(64), // v1 unused here
        signatureV2: h(s.expected_signature_v2),
        keyId: s.keyId,
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
      },
      oneTimePreKeys: [],
    };
    expect(verifySPKSignatureV2(bundle, { now: s.createdAt + 1000 })).toBe(true);
    // expired → rejected
    expect(verifySPKSignatureV2(bundle, { now: s.expiresAt + 1 })).toBe(false);
  });
});
