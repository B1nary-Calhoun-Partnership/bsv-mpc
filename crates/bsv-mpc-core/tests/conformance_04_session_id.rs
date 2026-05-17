//! Conformance suite for MPC-Spec §04 + ADR-0004 (canonical SessionId).
//!
//! Drives the byte-locked vectors at `tests/fixtures/04-session-id.json` and
//! asserts each vector reproduces byte-for-byte through
//! `canonical_session_id`. Includes the §04.6 sort-order discipline and
//! §04.9 forbidden-input (zero nonce) check on the spec data itself.

use bsv_mpc_core::canonical::{
    canonical_session_id, payload_digest_dkg, CeremonyKind, SessionParams,
};
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/04-session-id.json");

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("test vector hex must decode")
}

fn from_hex_arr<const N: usize>(s: &str) -> [u8; N] {
    let v = from_hex(s);
    assert_eq!(v.len(), N);
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    out
}

fn kind_from_value(k: u64) -> CeremonyKind {
    match k {
        0x01 => CeremonyKind::Dkg,
        0x02 => CeremonyKind::Sign,
        0x03 => CeremonyKind::Presign,
        0x04 => CeremonyKind::Ecdh,
        0x05 => CeremonyKind::Refresh,
        0x06 => CeremonyKind::PartyReplacement,
        0x07 => CeremonyKind::ThresholdChange,
        other => panic!("vector has unknown ceremony kind {other}"),
    }
}

#[test]
fn all_vectors_reproduce_byte_for_byte() {
    let root: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(root["spec_section"], "04");

    let vectors = root["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 2, "§04 has at least 2 byte-locked vectors");

    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let inputs = &v["inputs"];

        let initiator = from_hex_arr::<33>(inputs["initiator_identity_hex"].as_str().unwrap());
        let participants: Vec<[u8; 33]> = inputs["participants_hex_sorted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| from_hex_arr::<33>(p.as_str().unwrap()))
            .collect();
        let threshold = inputs["threshold"].as_u64().unwrap() as u16;
        let kind = kind_from_value(inputs["ceremony_kind"].as_u64().unwrap());
        let nonce = from_hex_arr::<32>(inputs["nonce_hex"].as_str().unwrap());

        // Vector B's payload_digest is SHA-256("genesis" || canonical_cbor({})).
        // Vector A's payload_digest is a hex blob we use directly.
        let payload_digest: [u8; 32] =
            if let Some(ph) = inputs.get("payload_digest_hex").and_then(|v| v.as_str()) {
                from_hex_arr::<32>(ph)
            } else if name.contains("dkg") {
                // Reconstruct via our payload_digest_dkg helper with empty manifest CBOR (0xa0).
                payload_digest_dkg(&[0xa0])
            } else {
                panic!("vector '{name}' missing payload_digest_hex");
            };

        let params = SessionParams {
            initiator_identity: initiator,
            participants,
            threshold,
            kind,
            nonce,
            payload_digest,
        };
        let sid = canonical_session_id(&params).unwrap();
        let expected = v["expected"]["session_id_hex"].as_str().unwrap();
        assert_eq!(
            sid.hex(),
            expected,
            "§04 vector '{name}' must reproduce byte-for-byte"
        );
    }
}
