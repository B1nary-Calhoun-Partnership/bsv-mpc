//! **#98 native repro — the iOS-sim presign-over-relay timeout, reproduced on macOS.**
//!
//! Issue #98: the genuine n-party 4-of-6 presign-over-relay TIMES OUT on the iOS
//! simulator ("timed out awaiting PresigBundle assembly over the relay") but works
//! macOS-native. The 2-of-2 sign-over-relay works on the sim; the Notaries are
//! healthy. The capstone test
//! `deployed_4of6_capstone_mainnet_e2e::ceremony_2notary_4of6_no_sats` runs the SAME
//! ceremony and PASSES — but it runs on `#[tokio::test(flavor="multi_thread",
//! worker_threads=12)]`. This test runs the IDENTICAL ceremony on a SINGLE-THREADED
//! executor, faithfully emulating how the iOS UniFFI runtime drives the FFI future.
//!
//! ## Why this is a faithful repro (not a contrived single-thread test)
//!
//! UniFFI 0.28's `#[uniffi::export(async_runtime="tokio")]` scaffolding does NOT
//! spawn the FFI future onto a multi-thread tokio runtime. It wraps it in
//! `async_compat::Compat::new(...)` and hands it to `rust_future_new`, where it is
//! polled by the FOREIGN (Swift) executor — one poll at a time, on the caller's
//! thread. `Compat::poll` only enters a tokio CONTEXT for the duration of each poll,
//! via `get_runtime_handle()`, which — absent an ambient runtime — returns the handle
//! of async-compat's process-global `tokio::runtime::Builder::new_current_thread()`
//! runtime (one thread, parked on `block_on(Pending)`). So every `tokio::spawn` the
//! relay coordinator issues (the WS recv-loops, the `MessageBoxListener` pumps, the
//! per-message decode adapters, the `spawn_blocking` JoinHandle drivers) shares ONE
//! cooperatively-scheduled thread. `worker_threads=12` hides any
//! starve-the-recv-loop bug; this single thread does not.
//!
//! Driving the ceremony here via `futures::executor::block_on(Compat::new(fut))`
//! reproduces that EXACT topology on macOS — no iOS build/deploy cycle needed.
//!
//! ## FINDING (2026-05-29): the single-threaded runtime is NOT the cause of #98
//!
//! BOTH gated variants below run the genuine n-party 4-of-6 presign-over-relay against
//! the LIVE Notaries and PASS end-to-end on macOS. `CLIENT_4OF6_CURRENT_THREAD=1` (the
//! faithful FFI emulation, `block_on(Compat::new(...))`) passed in ~499s with the presig
//! assembled and the sign verified; `CLIENT_4OF6_SINGLE_RT=1` (the literal
//! `new_current_thread().enable_all()` + `block_on`, the tightest single-thread
//! topology) passed in ~417s.
//!
//! This REFUTES the "single-threaded UniFFI runtime starves the WS recv-loop"
//! hypothesis: the presign coordinator already offloads its bignum/Paillier round math
//! to `tokio::task::spawn_blocking` (presign_handler.rs) and its WS recv-loops are real
//! `tokio::spawn`ed tasks, so a single COOPERATIVE async thread does not deadlock it.
//! The #98 stall is therefore iOS-SIMULATOR-PLATFORM-specific (slower CPU + native-tls
//! handshakes serializing the presign's many relay round-trips past the 360s budget,
//! and/or an Apple-sim TLS/WS-stack issue), NOT a runtime-topology bug reproducible on
//! macOS. These tests are kept as a permanent guard documenting that negative result.
//!
//! ## Gate + run
//!
//! ```bash
//! CLIENT_4OF6_CURRENT_THREAD=1 cargo test -p bsv-mpc-client --features native \
//!   --test issue98_current_thread_repro_e2e -- --nocapture --test-threads=1
//! ```
//!
//! Hits the LIVE Notaries + relay (no sats), ~5-6 min. BEFORE the fix it STALLS at
//! presig assembly exactly like the sim; AFTER the fix it completes + verifies.
#![cfg(all(not(target_arch = "wasm32"), feature = "native"))]

use std::sync::Arc;
use std::time::Duration;

use async_compat::Compat;
use bsv::primitives::ec::{PrivateKey, PublicKey, Signature};
use bsv_mpc_client::native_io::keystore::MemNativeKeyStore;
use bsv_mpc_client::native_io::provision::NpartyCosigner;
use bsv_mpc_client::native_io::signer::{DeployedSigner, DeployedSignerConfig, WalletMeta};
use bsv_mpc_core::types::{JointPublicKey, PolicyId, ThresholdConfig};

const NOTARY_A_URL: &str = "https://bsv-mpc-service-container.dev-a3e.workers.dev";
const NOTARY_B_URL: &str = "https://bsv-mpc-service-container-b.dev-a3e.workers.dev";
const NOTARY_A_MASTER: &str = "0278138e618ebb69c8bc6af07d15e50c72d9628b2c0fd7042185ee5cf5712af0e8";
const NOTARY_B_MASTER: &str = "034957e39818e8d073a025a5e9c99e99fadae20419150c3c1be89c259abaa4622f";
const DEFAULT_RELAY: &str = "https://rust-message-box.dev-a3e.workers.dev";
const AT_REST_ROOT: [u8; 32] = [0x4fu8; 32];
const T: u16 = 4;
const N: u16 = 6;

fn relay_url() -> String {
    std::env::var("MESSAGEBOX_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY.to_string())
}

/// The full ceremony as ONE async future — provision a genuine 4-of-6, top up one
/// presig set over the relay, sign a dummy digest, and verify under the joint key.
/// Identical to the capstone's `ceremony_2notary_4of6_no_sats`, factored so it can be
/// driven by the single-threaded FFI-emulating executor below.
async fn ceremony() {
    // Distinct device identity from the capstone's so concurrent runs don't collide.
    let identity = PrivateKey::from_bytes(&[0x98u8; 32]).expect("identity key");
    let keystore = Arc::new(MemNativeKeyStore::new());
    let config = ThresholdConfig::new(T, N).expect("4-of-6");

    eprintln!("[#98 repro] provisioning genuine 2-Notary 4-of-6 (live relay, #85-pinned)…");
    let w = bsv_mpc_client::native_io::provision_wallet_nparty(
        &relay_url(),
        identity.clone(),
        config,
        vec![0, 1, 2], // device holds w = t−1 = 3
        vec![
            NpartyCosigner {
                container_url: NOTARY_A_URL.to_string(),
                indices: vec![3, 4],
                expected_master_pub: Some(NOTARY_A_MASTER.to_string()),
            },
            NpartyCosigner {
                container_url: NOTARY_B_URL.to_string(),
                indices: vec![5],
                expected_master_pub: Some(NOTARY_B_MASTER.to_string()),
            },
        ],
        Duration::from_secs(700),
        keystore.as_ref(),
        None,
    )
    .await
    .expect("provision_wallet_nparty (2-Notary DKG + #85 verify + seal) MUST succeed");

    let joint = w.joint_key.clone();
    let mut joint_arr = [0u8; 33];
    joint_arr.copy_from_slice(&joint.compressed);
    let joint_pub = PublicKey::from_bytes(&joint_arr).expect("joint pubkey");
    eprintln!(
        "[#98 repro] ✔ provisioned: agent_id={} my_indices={:?}",
        w.agent_id, w.my_indices
    );

    let cosigner_party = 3u16;
    let mut participants = w.my_indices.clone();
    participants.push(cosigner_party);
    participants.sort_unstable();
    participants.dedup();
    let device_primary = *w.my_indices.first().expect("device holds indices");

    let bundle_dir = std::env::temp_dir().join(format!("bsvmpc-98-repro-{}", std::process::id()));
    let signer = DeployedSigner::connect(
        DeployedSignerConfig {
            relay_url: relay_url(),
            container_url: NOTARY_A_URL.to_string(),
            identity,
            at_rest_root: AT_REST_ROOT,
            bundle_dir,
            policy_id: PolicyId([0u8; 32]),
            meta: WalletMeta {
                agent_id: w.agent_id.clone(),
                joint_key: JointPublicKey {
                    compressed: joint.compressed.clone(),
                    address: joint.address.clone(),
                },
                config: w.config,
                participants,
                device_share_index: device_primary,
                my_indices: w.my_indices.clone(),
                cosigner_party,
                cosigner_master_pub: Some(NOTARY_A_MASTER.to_string()),
                dkg_session_id: w.dkg_session_id,
            },
        },
        keystore,
    )
    .await
    .expect("connect multi-index DeployedSigner to NotaryA");
    eprintln!(
        "[#98 repro] ✔ connected; running the n-party presign-over-relay (the #98 hot spot)…"
    );

    // THE GATE: on-demand n-party presign-over-relay + device-holds sign. This is
    // exactly where the iOS sim times out "awaiting PresigBundle assembly".
    let sighash = [0x7cu8; 32];
    let sig = signer
        .sign(
            &sighash,
            "Approve 4-of-6 #98 repro",
            None,
            Duration::from_secs(90),
            Duration::from_secs(360),
        )
        .await
        .expect("n-party presign + device-holds sign over the live relay (the #98 path)");

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r);
    s.copy_from_slice(&sig.s);
    let bsv_sig = Signature::new(r, s);
    assert!(bsv_sig.is_low_s(), "signature must be low-s");
    assert!(
        joint_pub.verify(&sighash, &bsv_sig),
        "the 4-of-6 signature MUST verify under the joint key"
    );
    eprintln!(
        "[#98 repro] ✔✔ presign + sign COMPLETED on a single-threaded FFI-emulating executor"
    );
}

/// Drive the ceremony the way the iOS UniFFI runtime does: a NON-tokio executor polls
/// a `Compat`-wrapped future; `tokio::spawn` lands on async-compat's process-global
/// `new_current_thread` runtime. This is the faithful #98 repro.
#[test]
fn issue98_current_thread_presign_over_relay() {
    if std::env::var("CLIENT_4OF6_CURRENT_THREAD").ok().as_deref() != Some("1") {
        eprintln!(
            "CLIENT_4OF6_CURRENT_THREAD=1 not set — skipping the #98 single-threaded repro.\n\
             To run (live Notaries + relay, no sats, ~5-6 min):\n  \
             CLIENT_4OF6_CURRENT_THREAD=1 cargo test -p bsv-mpc-client --features native \\\n  \
             --test issue98_current_thread_repro_e2e -- --nocapture --test-threads=1"
        );
        return;
    }
    // `futures::executor::block_on` is a NON-tokio executor (mirrors the foreign Swift
    // poller). `Compat::new` enters async-compat's global current-thread tokio context
    // per poll — the EXACT UniFFI 0.28 `async_runtime="tokio"` scaffolding mechanism.
    futures::executor::block_on(Compat::new(ceremony()));
}

/// The MOST starvation-prone configuration the task names: a literal
/// `new_current_thread().enable_all()` runtime driven by `block_on`. Here the top
/// future, EVERY `tokio::spawn`ed task (WS recv-loops, listener pumps, decode
/// adapters, `spawn_blocking` JoinHandle drivers), AND the IO/time drivers all share
/// exactly ONE thread — strictly tighter than the FFI/Compat path above (which gets a
/// second helper thread from async-compat's global runtime). If presign starves a
/// single async thread, this is where it shows.
#[test]
fn issue98_single_thread_runtime_presign_over_relay() {
    if std::env::var("CLIENT_4OF6_SINGLE_RT").ok().as_deref() != Some("1") {
        eprintln!(
            "CLIENT_4OF6_SINGLE_RT=1 not set — skipping the literal new_current_thread repro.\n\
             To run: CLIENT_4OF6_SINGLE_RT=1 cargo test -p bsv-mpc-client --features native \\\n  \
             --test issue98_current_thread_repro_e2e issue98_single_thread_runtime -- \\\n  \
             --nocapture --test-threads=1"
        );
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime");
    rt.block_on(ceremony());
}
