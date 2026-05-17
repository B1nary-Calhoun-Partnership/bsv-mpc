//! Conformance suite for MPC-Spec §02 + ADR-0003 (canonical ExecutionId).
//!
//! Drives the byte-locked vectors at `tests/fixtures/02-execution-id.json` and
//! asserts each vector reproduces byte-for-byte through
//! `canonical_execution_id`.

use bsv_mpc_core::canonical::{
    canonical_execution_id, AlgorithmTag, ExecutionParams, PhaseTag, SPEC_VERSION_V1,
};
use bsv_mpc_core::types::SessionId;
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/02-execution-id.json");

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("test vector hex must decode")
}

fn from_hex_arr<const N: usize>(s: &str) -> [u8; N] {
    let v = from_hex(s);
    assert_eq!(v.len(), N, "expected {N}-byte hex, got {} bytes", v.len());
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    out
}

fn phase_from_tag(tag: u64) -> PhaseTag {
    match tag {
        0x01 => PhaseTag::DkgKeygen,
        0x02 => PhaseTag::DkgAuxInfo,
        0x03 => PhaseTag::Presign,
        0x04 => PhaseTag::Sign,
        0x05 => PhaseTag::Ecdh,
        0x06 => PhaseTag::Refresh,
        other => panic!("vector has unknown phase tag {other}"),
    }
}

fn algorithm_from_tag(tag: u64) -> AlgorithmTag {
    match tag {
        0x01 => AlgorithmTag::Cggmp24,
        other => panic!("vector has unknown algorithm tag {other}"),
    }
}

#[test]
fn all_vectors_reproduce_byte_for_byte() {
    let root: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(root["spec_section"], "02");

    let vectors = root["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 3, "§02 has at least 3 byte-locked vectors");

    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let inputs = &v["inputs"];

        let version = inputs["version"].as_u64().unwrap() as u8;
        assert_eq!(
            version, SPEC_VERSION_V1,
            "vector '{name}' uses non-v1 spec version"
        );

        let phase = phase_from_tag(inputs["phase_tag"].as_u64().unwrap());
        let algorithm = algorithm_from_tag(inputs["algorithm_tag"].as_u64().unwrap());
        let session_id = SessionId(from_hex_arr::<32>(
            inputs["session_id_hex"].as_str().unwrap(),
        ));
        let joint_pubkey = from_hex_arr::<33>(inputs["joint_pubkey_hex"].as_str().unwrap());

        let params = ExecutionParams {
            version,
            algorithm,
            phase,
            session_id,
            joint_pubkey,
        };

        let eid = canonical_execution_id(&params);
        let expected_hex = v["expected"]["execution_id_hex"].as_str().unwrap();
        assert_eq!(
            hex::encode(eid),
            expected_hex,
            "§02 vector '{name}' must reproduce byte-for-byte"
        );
    }
}
