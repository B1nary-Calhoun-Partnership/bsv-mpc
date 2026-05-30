//! **#102 fund-safety gate** — an n-party **composite** share `{agent_id}#{index}`
//! survives an ephemeral-container restart via durable KEK-wrapped custody on the
//! worker DO. The sibling of the #9 bare-`share_A` gate
//! (`bsv-mpc-proxy/tests/custody_restart_survival_e2e.rs`), for the composite key
//! that #102 brings under durable custody.
//!
//! Restart is simulated with two `AppState`s sharing the SAME custody identity/KEK,
//! talking to the REAL deployed worker custody endpoints (this hits the WORKER DO,
//! not the notary containers — so it's independent of any notary redeploy):
//!
//! 1. **State A** persists a composite share via the #102 durable seam
//!    (`shares().persist_durable_at_index`) → custody-PUT to the DO + hot cache.
//! 2. **Drop A** (≡ container death — its in-memory cache is gone).
//! 3. **State B** — fresh empty cache, SAME custody root — i.e. the "restarted
//!    container". `shares().load_or_recover_at_index` MISSES the cache and RECOVERS
//!    the composite share from the DO, re-binding the §08.1 owner.
//!
//! Asserts: the recovered share matches byte-for-byte; the owner binding survived;
//! a DIFFERENT index does NOT recover (key isolation on the real DO). No DKG, no
//! sats — a direct custody round-trip, fast + reliable.
//!
//! Gated on `CUSTODY_E2E=1` (needs the deployed worker):
//! ```bash
//! CUSTODY_E2E=1 cargo test -p bsv-mpc-service \
//!   --test composite_custody_restart_e2e -- --nocapture --test-threads=1
//! ```
#![cfg(not(target_arch = "wasm32"))]

use std::sync::{Arc, RwLock};

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::brc31_client::Brc31Client;
use bsv_mpc_core::types::{EncryptedShare, SessionId, ShareIndex, ThresholdConfig};
use bsv_mpc_service::{AppState, AuthState, CustodyConfig, SqliteShareStorage};

const DEFAULT_WORKER: &str = "https://bsv-mpc-kss.dev-a3e.workers.dev";

fn key_from(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte | 1; 32]).expect("valid key")
}

/// Build an in-process `AppState` with durable custody → `worker_url`, using
/// `server_byte` as the custody root (server identity + KEK) — A and B share it so
/// B is "the same cosigner, restarted".
fn build_state(server_byte: u8, worker_url: &str, tag: &str) -> Arc<AppState> {
    let data_dir =
        std::env::temp_dir().join(format!("composite_custody_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let storage = SqliteShareStorage::open(data_dir.to_str().unwrap()).unwrap();
    let kek = bsv_mpc_core::custody::derive_custody_kek(&[server_byte | 1; 32]);
    Arc::new(AppState {
        data_dir: data_dir.to_string_lossy().to_string(),
        storage: Arc::new(RwLock::new(storage)),
        started_at: chrono::Utc::now(),
        provision: None,
        auth: AuthState::with_key(key_from(server_byte)),
        custody: Some(CustodyConfig {
            worker_url: worker_url.to_string(),
            kek,
            auth: tokio::sync::Mutex::new(Brc31Client::new(key_from(server_byte))),
            http: reqwest::Client::new(),
        }),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn composite_share_survives_restart_via_custody() {
    if std::env::var("CUSTODY_E2E").ok().as_deref() != Some("1") {
        eprintln!("CUSTODY_E2E=1 not set — skipping the #102 composite-custody restart gate.");
        return;
    }
    let worker =
        std::env::var("DEPLOYED_WORKER_URL").unwrap_or_else(|_| DEFAULT_WORKER.to_string());
    let server_byte = 0x9c; // custody root shared by A + B

    // Fresh random agent_id (a valid compressed pubkey hex) per run → no DO-side
    // collision with prior runs; index 4 (an n-party held index).
    let agent_id = {
        use rand::RngCore;
        let mut sk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sk);
        sk[0] |= 1;
        hex::encode(key_from_bytes(&sk).public_key().to_compressed())
    };
    let index: u16 = 4;
    let owner = key_from(0x11).public_key().to_hex();
    // Opaque share payload — the seam stores/recovers it byte-for-byte (it does not
    // parse it), so a distinctive marker proves the exact round-trip.
    let share = EncryptedShare {
        nonce: vec![0u8; 12],
        ciphertext: b"#102-composite-share-survives-restart".to_vec(),
        session_id: SessionId::from_bytes([0x9c; 32]),
        share_index: ShareIndex(index),
        config: ThresholdConfig::new(4, 6).unwrap(),
        joint_pubkey_compressed: vec![],
    };

    // ── 1. State A: durably custody the COMPOSITE share to the deployed DO. ──
    let a = build_state(server_byte, &worker, "A");
    a.shares()
        .persist_durable_at_index(&agent_id, index, &share, &owner)
        .await
        .expect("composite persist_durable (custody-PUT to deployed DO)");
    eprintln!("✔ A: composite share {agent_id}#{index} durably custodied to the DO");
    drop(a); // ≡ container death — in-memory cache gone.
    eprintln!("✔ A dropped (simulated container restart)");

    // ── 2. State B: fresh cache, SAME custody root → recover from the DO. ──
    let b = build_state(server_byte, &worker, "B");
    let recovered = b
        .shares()
        .load_or_recover_at_index(&agent_id, index)
        .await
        .expect("composite load_or_recover (custody GET from deployed DO)")
        .expect("composite share MUST recover from durable custody after restart");
    assert_eq!(
        recovered.ciphertext, share.ciphertext,
        "recovered composite share must match byte-for-byte"
    );
    // The §08.1 owner binding survived the recovery (re-bound into B's cache).
    let recovered_owner = b
        .storage
        .read()
        .unwrap()
        .get_share_owner_at_index(&agent_id, index)
        .unwrap();
    assert_eq!(
        recovered_owner.as_deref(),
        Some(owner.as_str()),
        "owner binding must survive composite custody recovery"
    );
    // Key isolation: a DIFFERENT held index does NOT recover (distinct DO record).
    assert!(
        b.shares()
            .load_or_recover_at_index(&agent_id, 5)
            .await
            .unwrap()
            .is_none(),
        "a different composite index must not recover (key isolation on the real DO)"
    );
    eprintln!(
        "✔ #102 GATE PASS — composite share {agent_id}#{index} survived restart via durable \
         KEK-custody (owner re-bound; index-isolated)"
    );
}

fn key_from_bytes(b: &[u8; 32]) -> PrivateKey {
    PrivateKey::from_bytes(b).expect("valid key")
}
