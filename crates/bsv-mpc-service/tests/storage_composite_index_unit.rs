//! #69 PR-2 step 1 — composite `(agent_id, share_index)` storage keying.
//!
//! The load-bearing PR-2 storage bug (risk review, HIGH): a cosigner — or the
//! device — holding `w > 1` indices of ONE ceremony has the SAME joint pubkey
//! (hence the same `agent_id`) for every held share, so the `agent_id`-keyed
//! store silently OVERWRITES `w−1` of them (last write wins). Per ADR-0052 a
//! 4-of-6 where a notary holds `{3,4}` MUST persist + load both.
//!
//! These tests pin: (1) two indices under one `agent_id` coexist with NO
//! overwrite and are independently loadable; (2) the legacy single-index
//! (`agent_id`-keyed) path is byte-for-byte UNCHANGED and lives in a separate
//! namespace from the composite keys (existing 2-of-2 / reshare / refresh
//! shares are unaffected).

use bsv_mpc_core::types::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_service::SqliteShareStorage;

/// A distinct `EncryptedShare` per (index, tag) so overwrites are detectable.
fn share(
    index: u16,
    joint: &[u8],
    session: SessionId,
    config: ThresholdConfig,
    tag: u8,
) -> EncryptedShare {
    EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: vec![tag; 8],
        session_id: session,
        share_index: ShareIndex(index),
        config,
        joint_pubkey_compressed: joint.to_vec(),
    }
}

/// 66-hex-char (33-byte compressed pubkey) agent id — the real shape; contains
/// no `#`, so a composite `agent_id#index` key can never collide with a bare one.
fn agent_id(prefix2: &str, byte: &str) -> String {
    format!("{prefix2}{}", byte.repeat(32))
}

#[test]
fn two_indices_same_agent_id_no_overwrite() {
    let mut st = SqliteShareStorage::open("/tmp/bsv-mpc-composite-test").expect("open in-mem");
    let config = ThresholdConfig::new(4, 6).expect("4-of-6");
    let session = SessionId::from_str_hash("composite-keying-test");
    let joint = vec![0x02u8; 33];
    let agent = agent_id("02", "ab");

    let s3 = share(3, &joint, session, config, 0x31);
    let s4 = share(4, &joint, session, config, 0x42);

    // Same agent_id (same joint pubkey), two DIFFERENT held indices.
    st.store_share_at_index(&agent, 3, &s3, "owner-A")
        .expect("store idx 3");
    st.store_share_at_index(&agent, 4, &s4, "owner-A")
        .expect("store idx 4");

    let g3 = st
        .get_share_at_index(&agent, 3)
        .expect("get idx 3")
        .expect("index 3 present");
    let g4 = st
        .get_share_at_index(&agent, 4)
        .expect("get idx 4")
        .expect("index 4 present — NOT overwritten by idx 3 or vice versa");

    assert_eq!(g3.share_index, ShareIndex(3));
    assert_eq!(g4.share_index, ShareIndex(4));
    assert_eq!(g3.ciphertext, vec![0x31u8; 8]);
    assert_eq!(g4.ciphertext, vec![0x42u8; 8]);
    assert_ne!(
        g3.ciphertext, g4.ciphertext,
        "the two held shares must remain distinct (no last-write-wins overwrite)"
    );

    // held_indices reports exactly the persisted set, sorted.
    assert_eq!(
        st.held_indices(&agent).expect("held_indices"),
        vec![3, 4],
        "held_indices must enumerate every persisted index for the agent"
    );

    // owner recorded per composite slot.
    assert_eq!(
        st.get_share_owner_at_index(&agent, 3)
            .expect("owner idx 3")
            .as_deref(),
        Some("owner-A"),
    );
}

#[test]
fn single_index_legacy_path_unchanged_and_namespaced() {
    let mut st = SqliteShareStorage::open("/tmp/bsv-mpc-legacy-test").expect("open in-mem");
    let config = ThresholdConfig::new(2, 2).expect("2-of-2");
    let session = SessionId::from_str_hash("legacy-keying-test");
    let joint = vec![0x03u8; 33];
    let agent = agent_id("03", "cd");

    // Legacy agent-keyed path — byte-for-byte the existing 2-of-2 / reshare API.
    let s = share(1, &joint, session, config, 0x55);
    st.store_share(&agent, &s).expect("legacy store");
    let g = st
        .get_share(&agent)
        .expect("legacy get")
        .expect("legacy share present");
    assert_eq!(g.share_index, ShareIndex(1));
    assert_eq!(g.ciphertext, vec![0x55u8; 8]);

    // The legacy bare-agent share must NOT be visible through the composite
    // namespace (independent namespaces — composite never shadows or is shadowed
    // by legacy). This is what guarantees zero regression for existing shares.
    assert!(
        st.get_share_at_index(&agent, 1)
            .expect("composite get")
            .is_none(),
        "legacy agent-keyed share must be invisible via composite key"
    );
    assert!(
        st.held_indices(&agent).expect("held_indices").is_empty(),
        "a legacy (bare-agent) share contributes no composite held_indices"
    );
}
