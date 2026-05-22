//! **Within-stack 2-of-3 DKG e2e via MessageBox** — M1 (MPC-Spec #12) gate.
//!
//! The 3-party generalization of `dkg_via_messagebox_e2e`. Boots Alice (0),
//! Bob (1), Carol (2) as in-process bsv-mpc-service participants — each with a
//! live `MessageBoxClient` (own BRC-31 identity against the deployed Calhoun
//! relay), a `DkgHandler`, and a `MessageBoxListener`. Each `initiate`s with the
//! OTHER TWO as peers; round-1 broadcasts fan out to both, and the n-party
//! routing (broadcast→all peers, p2p→named peer for threshold-keygen VSS shares)
//! drives a real CGGMP'24 2-of-3 keygen+auxinfo to completion.
//!
//! For the M1 demo, one of the three parties stands in for Binary's cosigner —
//! it runs bsv-mpc, so this is a faithful 2-of-3 ceremony on the canonical wire.
//!
//! **Merge gate:** byte-identical `joint_pubkey` on ALL THREE parties + each
//! party's share persisted at its own index.
//!
//! Gated on `MESSAGEBOX_RELAY_URL` (no sats — DKG only). Run with:
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-service --test dkg_2of3_via_messagebox_e2e \
//!     -- --nocapture --test-threads=1
//! ```
//! Wall-clock ~90-150s (three Paillier safe-prime sets dominate; generated in
//! parallel).

use std::sync::Arc;
use std::time::Duration;

use bsv::primitives::ec::PrivateKey;
use bsv_mpc_core::types::{DkgResult, SessionId, ThresholdConfig};
use bsv_mpc_messagebox::types::BOX_DKG;
use bsv_mpc_messagebox::MessageBoxClient;
use bsv_mpc_service::storage::SqliteShareStorage;
use bsv_mpc_service::{DkgHandler, MessageBoxListener};
use cggmp24::security_level::SecurityLevel128;
use cggmp24::PregeneratedPrimes;
use rand::RngCore;
use tempfile::TempDir;
use tokio::sync::oneshot;

fn relay_url() -> Option<String> {
    std::env::var("MESSAGEBOX_RELAY_URL").ok()
}

fn fresh_priv() -> PrivateKey {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[0] |= 0x01;
    PrivateKey::from_bytes(&b).expect("fresh priv must be valid")
}

fn fresh_storage() -> (Arc<std::sync::RwLock<SqliteShareStorage>>, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = SqliteShareStorage::open(dir.path().to_str().unwrap()).expect("open");
    (Arc::new(std::sync::RwLock::new(storage)), dir)
}

/// One booted party: live client + handler + listener + identity + storage.
struct Party {
    name: &'static str,
    index: u16,
    client: MessageBoxClient,
    handler: DkgHandler,
    listener: MessageBoxListener,
    pub_hex: String,
    storage: Arc<std::sync::RwLock<SqliteShareStorage>>,
    _dir: TempDir,
}

#[tokio::test]
async fn within_stack_2of3_dkg_byte_identical_joint_pubkey() {
    let Some(relay_url) = relay_url() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL not set — skipping M1 2-of-3 DKG e2e. \
             To run: MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
             cargo test -p bsv-mpc-service --test dkg_2of3_via_messagebox_e2e \
             -- --nocapture --test-threads=1"
        );
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();

    let config = ThresholdConfig::new(2, 3).expect("valid 2-of-3 config");
    let names = ["alice", "bob", "carol"];

    // ----- Identities + storage for all three -----
    let mut clients = Vec::new();
    let mut pub_hexes = Vec::new();
    let mut storages = Vec::new();
    let mut dirs = Vec::new();
    for name in names {
        let client = MessageBoxClient::new(&relay_url, fresh_priv())
            .unwrap_or_else(|e| panic!("{name} client: {e}"));
        let pub_hex = client
            .identity_hex()
            .await
            .unwrap_or_else(|e| panic!("{name} identity_hex: {e}"));
        eprintln!("✔ {name} = {pub_hex}");
        let (storage, dir) = fresh_storage();
        clients.push(client);
        pub_hexes.push(pub_hex);
        storages.push(storage);
        dirs.push(dir);
    }

    // ----- Pre-generate three Paillier prime sets in parallel -----
    eprintln!("(generating 3 Paillier safe-prime sets — the slow step, ~30-90s each, parallel)");
    let primes_t0 = std::time::Instant::now();
    let mut primes = tokio::task::spawn_blocking(|| {
        let handles: Vec<_> = (0..3)
            .map(|_| {
                std::thread::spawn(|| {
                    PregeneratedPrimes::<SecurityLevel128>::generate(&mut rand::rngs::OsRng)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("prime thread panicked"))
            .collect::<Vec<_>>()
    })
    .await
    .expect("prime gen task panicked");
    eprintln!("✔ generated 3 prime sets in {:?}", primes_t0.elapsed());

    let session_id = {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        SessionId(b)
    };
    eprintln!(
        "✔ ceremony session_id = {}",
        hex::encode(session_id.as_bytes())
    );

    // ----- Build handlers + seed primes + start listeners BEFORE initiate -----
    let mut parties: Vec<Party> = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let idx = i as u16;
        let handler = DkgHandler::new(config, idx, storages[i].clone());
        handler.seed_primes_for(session_id, primes.remove(0));
        let listener = MessageBoxListener::start(clients[i].clone(), BOX_DKG, handler.handler_fn())
            .await
            .unwrap_or_else(|e| panic!("{name} listener: {e}"));
        parties.push(Party {
            name,
            index: idx,
            client: clients[i].clone(),
            handler,
            listener,
            pub_hex: pub_hexes[i].clone(),
            storage: storages[i].clone(),
            _dir: dirs.remove(0),
        });
    }
    eprintln!("✔ all three listeners live");

    // ----- Each party initiates with the OTHER TWO as peers -----
    // Initiate ALL parties FIRST so every coordinator exists before any round-1
    // message flows. Otherwise a round-1 message can reach a peer that hasn't
    // called initiate yet and be dropped as "unknown session" → the ceremony
    // stalls. (The 2-party test relies on the same ordering invariant.)
    let dkg_t0 = std::time::Instant::now();
    let mut completions: Vec<(u16, oneshot::Receiver<DkgResult>)> = Vec::new();
    let mut pending_sends = Vec::new();
    for i in 0..parties.len() {
        let peers: Vec<(u16, String)> = parties
            .iter()
            .filter(|p| p.index != parties[i].index)
            .map(|p| (p.index, p.pub_hex.clone()))
            .collect();
        let (rx, outbound) = parties[i]
            .handler
            .initiate(session_id, peers)
            .await
            .unwrap_or_else(|e| panic!("{} initiate: {e}", parties[i].name));
        assert!(
            !outbound.is_empty(),
            "{} must produce round-1 outbound",
            parties[i].name
        );
        completions.push((parties[i].index, rx));
        pending_sends.push((i, outbound));
    }
    // Now every coordinator is live — ship all round-1 messages (each broadcast
    // fans out to both peers via the n-party routing).
    for (i, outbound) in pending_sends {
        for out in outbound {
            parties[i]
                .client
                .send_round_message(
                    &out.recipient_pub_hex,
                    &out.message_box,
                    &out.round_msg,
                    out.params,
                )
                .await
                .unwrap_or_else(|e| panic!("{} round-1 send: {e}", parties[i].name));
        }
    }
    eprintln!("✔ all three initiated + round-1 shipped — listeners drive the ceremony");

    // ----- Wait for all three completions -----
    let dkg_timeout = Duration::from_secs(300);
    let mut results: Vec<(u16, DkgResult)> = Vec::new();
    for (idx, rx) in completions {
        let res = tokio::time::timeout(dkg_timeout, rx)
            .await
            .unwrap_or_else(|_| panic!("party {idx} DKG MUST complete within timeout"))
            .unwrap_or_else(|_| panic!("party {idx} completion channel dropped"));
        results.push((idx, res));
    }
    eprintln!("✔ all three ceremonies complete in {:?}", dkg_t0.elapsed());

    // ----- THE GATE: byte-identical joint_pubkey across ALL THREE -----
    let jpk0 = &results[0].1.joint_key.compressed;
    for (idx, r) in &results {
        assert_eq!(
            &r.joint_key.compressed, jpk0,
            "party {idx} joint_pubkey MUST be byte-identical to party 0 — \
             proves the 2-of-3 DKG over MessageBox actually agreed"
        );
    }
    eprintln!(
        "✔✔ 2-of-3 JOINT KEY AGREED across all three — joint_pubkey={} address={}",
        hex::encode(jpk0),
        results[0].1.joint_key.address
    );

    // ----- Each party's share persisted at its own index -----
    let session_hex = results[0].1.session_id.hex();
    for party in &parties {
        let store = party.storage.read().unwrap();
        let stored = store
            .get_share(&session_hex)
            .expect("storage get_share")
            .unwrap_or_else(|| panic!("{} share MUST be persisted", party.name));
        assert_eq!(
            stored.share_index.0, party.index,
            "{} stored share index",
            party.name
        );
        assert_eq!(
            party.handler.live_session_count(),
            0,
            "{} cleaned up",
            party.name
        );
    }
    eprintln!("✔ all three shares persisted (session {session_hex})");

    // ----- Cleanup -----
    for party in parties {
        let _ = tokio::time::timeout(Duration::from_secs(10), party.listener.shutdown()).await;
    }
    eprintln!(
        "✔ done — total wall-clock {:?} (primes-dominated)",
        t0.elapsed()
    );
}
