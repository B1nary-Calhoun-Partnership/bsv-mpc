//! **Within-stack 4-of-6 DKG e2e via MessageBox** — #69 PR-2 step 4 (the §06.22 /
//! ADR-0052 genuine-n-party-DKG-over-relay gate).
//!
//! The 6-party generalization of `dkg_2of3_via_messagebox_e2e`. Boots all SIX
//! keygen parties of a `(t=4, n=6)` ceremony as in-process participants — each
//! with a live `MessageBoxClient` (own BRC-31 identity against the deployed
//! Calhoun relay), a `DkgHandler`, and a `MessageBoxListener`. Each `initiate`s
//! with the OTHER FIVE as peers; broadcasts fan out to all five and the n-party
//! routing (broadcast→all, p2p→named peer for threshold-keygen VSS shares) drives
//! a real CGGMP'24 4-of-6 keygen+auxinfo to completion.
//!
//! This is the wire proof for ADR-0052 Model B: a device backing `w = t−1 = 3`
//! indices `{0,1,2}` is just three ordinary keygen parties with their own
//! identities (here parties 0,1,2 stand in for the device; 3,4,5 for the
//! Notaries) — the DKG is symmetric and never sees the co-location. The
//! device-alone set `{0,1,2}` is `3 < t = 4`, i.e. sub-threshold (the
//! "two mandatory sides" guarantee; the sign-side negative is the merged
//! `device_holds_combine` kernel's job).
//!
//! **Merge gate:** byte-identical `joint_pubkey` on ALL SIX parties + each
//! party's share persisted at its own index.
//!
//! Gated on `MESSAGEBOX_RELAY_URL` (no sats — DKG only). Run with:
//! ```bash
//! MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
//!   cargo test -p bsv-mpc-service --test dkg_4of6_via_messagebox_e2e \
//!     -- --nocapture --test-threads=1
//! ```
//! Wall-clock ~3-6 min (six Paillier safe-prime sets dominate; generated in parallel).

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

const T: u16 = 4;
const N: u16 = 6;
/// The device-holds-(t−1) indices for the ADR-0052 framing (device backs {0,1,2}).
const DEVICE_INDICES: [u16; 3] = [0, 1, 2];

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

struct Party {
    name: String,
    index: u16,
    client: MessageBoxClient,
    handler: DkgHandler,
    listener: MessageBoxListener,
    pub_hex: String,
    storage: Arc<std::sync::RwLock<SqliteShareStorage>>,
    _dir: TempDir,
}

#[tokio::test]
async fn within_stack_4of6_dkg_byte_identical_joint_pubkey() {
    let Some(relay_url) = relay_url() else {
        eprintln!(
            "MESSAGEBOX_RELAY_URL not set — skipping #69 PR-2 4-of-6 DKG e2e. \
             To run: MESSAGEBOX_RELAY_URL=https://rust-message-box.dev-a3e.workers.dev \
             cargo test -p bsv-mpc-service --test dkg_4of6_via_messagebox_e2e \
             -- --nocapture --test-threads=1"
        );
        return;
    };
    let _ = tracing_subscriber::fmt::try_init();
    let t0 = std::time::Instant::now();

    // device-holds framing sanity: device backs exactly t−1 indices.
    assert_eq!(DEVICE_INDICES.len() as u16, T - 1, "device holds w = t−1");
    assert!(
        (DEVICE_INDICES.len() as u16) < T,
        "device-alone {DEVICE_INDICES:?} ({}) is sub-threshold (< t={T}) — two mandatory sides",
        DEVICE_INDICES.len()
    );

    let config = ThresholdConfig::new(T, N).expect("valid 4-of-6 config");
    let names: Vec<String> = (0..N)
        .map(|i| {
            if DEVICE_INDICES.contains(&i) {
                format!("device-{i}")
            } else {
                format!("notary-{i}")
            }
        })
        .collect();

    // ----- Identities + storage for all six -----
    let mut clients = Vec::new();
    let mut pub_hexes = Vec::new();
    let mut storages = Vec::new();
    let mut dirs = Vec::new();
    for name in &names {
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

    // ----- Pre-generate six Paillier prime sets in parallel -----
    eprintln!("(generating {N} Paillier safe-prime sets — the slow step, ~30-90s each, parallel)");
    let primes_t0 = std::time::Instant::now();
    let mut primes = tokio::task::spawn_blocking(|| {
        let handles: Vec<_> = (0..N)
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
    eprintln!("✔ generated {N} prime sets in {:?}", primes_t0.elapsed());

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
            name: name.clone(),
            index: idx,
            client: clients[i].clone(),
            handler,
            listener,
            pub_hex: pub_hexes[i].clone(),
            storage: storages[i].clone(),
            _dir: dirs.remove(0),
        });
    }
    eprintln!("✔ all {N} listeners live");

    // ----- Each party initiates with the OTHER FIVE as peers (initiate ALL first) -----
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
    eprintln!("✔ all {N} initiated + round-1 shipped — listeners drive the ceremony");

    // ----- Wait for all six completions -----
    let dkg_timeout = Duration::from_secs(420);
    let mut results: Vec<(u16, DkgResult)> = Vec::new();
    for (idx, rx) in completions {
        let res = tokio::time::timeout(dkg_timeout, rx)
            .await
            .unwrap_or_else(|_| panic!("party {idx} DKG MUST complete within timeout"))
            .unwrap_or_else(|_| panic!("party {idx} completion channel dropped"));
        results.push((idx, res));
    }
    eprintln!("✔ all {N} ceremonies complete in {:?}", dkg_t0.elapsed());

    // ----- THE GATE: byte-identical joint_pubkey across ALL SIX -----
    let jpk0 = &results[0].1.joint_key.compressed;
    for (idx, r) in &results {
        assert_eq!(
            &r.joint_key.compressed, jpk0,
            "party {idx} joint_pubkey MUST be byte-identical to party 0 — \
             proves the genuine 6-party 4-of-6 DKG over MessageBox actually agreed"
        );
    }
    eprintln!(
        "✔✔ 4-of-6 JOINT KEY AGREED across all {N} — joint_pubkey={} address={}",
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
    eprintln!("✔ all {N} shares persisted (session {session_hex})");

    // ----- Cleanup -----
    for party in parties {
        let _ = tokio::time::timeout(Duration::from_secs(10), party.listener.shutdown()).await;
    }
    eprintln!(
        "✔ done — total wall-clock {:?} (primes-dominated). Device backs {DEVICE_INDICES:?} (w=t−1); \
         co-location is invisible to this symmetric 6-party DKG (ADR-0052 Model B).",
        t0.elapsed()
    );
}
