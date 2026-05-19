//! Inline 2-party state-machine drive — no thread spawn anywhere.
//!
//! Two parties' SMs both live in the same OS thread. Messages are
//! exchanged through in-process `VecDeque`s. Each party drives its SM
//! via direct `proceed()` + `received_msg()` calls.
//!
//! This proves the Phase G claim that `round_based::StateMachine`
//! does not need `std::thread::spawn` — `proceed()` is non-blocking,
//! and the existing thread+mpsc bridge in
//! `crates/bsv-mpc-core/src/dkg.rs:759-908` (and signing/presigning
//! analogues) was incidental complexity.

use std::collections::VecDeque;

use cggmp24::key_refresh::PregeneratedPrimes;
use cggmp24::key_share::AuxInfo;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::supported_curves::Secp256k1;
use cggmp24::ExecutionId;
use cggmp24::IncompleteKeyShare;
use round_based::state_machine::{ProceedResult, StateMachine};
use round_based::{Incoming, MessageType};

/// Errors that can arise driving the SMs inline. Distinct from the
/// production `MpcError` enum so the POC stays self-contained.
#[derive(Debug, thiserror::Error)]
pub enum InlineDriveError {
    #[error("party {0} state machine error: {1}")]
    SmError(u16, String),
    #[error("party {0} rejected incoming message")]
    RejectedMsg(u16),
    #[error("inline drive stalled (no party made progress in a full cycle)")]
    Stalled,
    #[error("party {0} returned protocol error: {1}")]
    ProtocolError(u16, String),
}

/// Drive a 2-of-2 DKG keygen inline. Both parties' SMs run in the same
/// thread; messages flow through in-process queues. Returns the two
/// parties' `IncompleteKeyShare` outputs on success.
///
/// Gate G-3.1: this function has **zero `std::thread::spawn` or
/// `tokio::spawn` calls** anywhere in its call graph. Verified by
/// `tests/poc.rs::gate_3_1_no_thread_or_tokio_spawn_in_source`.
pub fn run_inline_2of2_keygen(
    eid_bytes: [u8; 32],
) -> Result<(IncompleteKeyShare<Secp256k1>, IncompleteKeyShare<Secp256k1>), InlineDriveError> {
    let eid = ExecutionId::new(&eid_bytes);
    let n: u16 = 2;
    let t: u16 = 2;

    // Each party's rng must outlive its SM (the SM borrows it for its
    // lifetime via `.into_state_machine(&mut rng)`).
    let mut rng_a = rand::rngs::OsRng;
    let mut rng_b = rand::rngs::OsRng;

    let mut sm_a = cggmp24::keygen::<Secp256k1>(eid, 0, n)
        .set_threshold(t)
        .into_state_machine(&mut rng_a);
    let mut sm_b = cggmp24::keygen::<Secp256k1>(eid, 1, n)
        .set_threshold(t)
        .into_state_machine(&mut rng_b);

    let mut to_a: VecDeque<Incoming<_>> = VecDeque::new();
    let mut to_b: VecDeque<Incoming<_>> = VecDeque::new();

    let mut share_a = None;
    let mut share_b = None;
    let mut next_id: u64 = 0;

    loop {
        let mut progressed = false;

        if share_a.is_none() {
            progressed |= drive_one_party(
                0,
                &mut sm_a,
                &mut to_a,
                &mut to_b,
                &mut share_a,
                &mut next_id,
            )?;
        }
        if share_b.is_none() {
            progressed |= drive_one_party(
                1,
                &mut sm_b,
                &mut to_b,
                &mut to_a,
                &mut share_b,
                &mut next_id,
            )?;
        }

        match (share_a.take(), share_b.take()) {
            (Some(a), Some(b)) => return Ok((a, b)),
            (a, b) => {
                share_a = a;
                share_b = b;
            }
        }
        if !progressed {
            return Err(InlineDriveError::Stalled);
        }
    }
}

/// Drive a 2-party `aux_info_gen` inline using injected
/// `PregeneratedPrimes`. The shape mirrors [`run_inline_2of2_keygen`].
///
/// Gate G-3.2: proves `aux_info_gen` runs to completion with primes
/// supplied via `PregeneratedPrimes::TryFrom<[Integer; 4]>` (the
/// injection path) rather than `PregeneratedPrimes::generate(rng)`.
pub fn run_inline_2of2_auxinfo(
    eid_bytes: [u8; 32],
    primes_a: PregeneratedPrimes<SecurityLevel128>,
    primes_b: PregeneratedPrimes<SecurityLevel128>,
) -> Result<(AuxInfo<SecurityLevel128>, AuxInfo<SecurityLevel128>), InlineDriveError> {
    let eid = ExecutionId::new(&eid_bytes);
    let n: u16 = 2;

    let mut rng_a = rand::rngs::OsRng;
    let mut rng_b = rand::rngs::OsRng;

    let mut sm_a = cggmp24::aux_info_gen::<SecurityLevel128>(eid, 0, n, primes_a)
        .into_state_machine(&mut rng_a);
    let mut sm_b = cggmp24::aux_info_gen::<SecurityLevel128>(eid, 1, n, primes_b)
        .into_state_machine(&mut rng_b);

    let mut to_a: VecDeque<Incoming<_>> = VecDeque::new();
    let mut to_b: VecDeque<Incoming<_>> = VecDeque::new();

    let mut aux_a = None;
    let mut aux_b = None;
    let mut next_id: u64 = 0;

    loop {
        let mut progressed = false;

        if aux_a.is_none() {
            progressed |=
                drive_one_party(0, &mut sm_a, &mut to_a, &mut to_b, &mut aux_a, &mut next_id)?;
        }
        if aux_b.is_none() {
            progressed |=
                drive_one_party(1, &mut sm_b, &mut to_b, &mut to_a, &mut aux_b, &mut next_id)?;
        }

        match (aux_a.take(), aux_b.take()) {
            (Some(a), Some(b)) => return Ok((a, b)),
            (a, b) => {
                aux_a = a;
                aux_b = b;
            }
        }
        if !progressed {
            return Err(InlineDriveError::Stalled);
        }
    }
}

/// Drive a single party's SM until it either needs an incoming message
/// (which isn't in its queue) or completes. Returns `true` if any
/// progress was made (at least one `proceed()` did NOT block waiting on
/// an empty queue).
///
/// This is the kernel of the inline-drive pattern. The production
/// rewrite in `crates/bsv-mpc-core/src/dkg.rs` will host the SM on a
/// coordinator struct and call this body from `process_round()`; the
/// POC inlines both parties' loops for simplicity.
fn drive_one_party<O, E, M, SM>(
    party_index: u16,
    sm: &mut SM,
    inbox: &mut VecDeque<Incoming<M>>,
    outbox: &mut VecDeque<Incoming<M>>,
    completed: &mut Option<O>,
    next_id: &mut u64,
) -> Result<bool, InlineDriveError>
where
    SM: StateMachine<Output = Result<O, E>, Msg = M>,
    E: std::fmt::Display,
{
    let mut progressed = false;
    loop {
        match sm.proceed() {
            ProceedResult::SendMsg(out) => {
                *next_id += 1;
                let msg_type = if out.recipient.is_broadcast() {
                    MessageType::Broadcast
                } else {
                    MessageType::P2P
                };
                outbox.push_back(Incoming {
                    id: *next_id,
                    sender: party_index,
                    msg_type,
                    msg: out.msg,
                });
                progressed = true;
            }
            ProceedResult::NeedsOneMoreMessage => {
                if let Some(inc) = inbox.pop_front() {
                    sm.received_msg(inc)
                        .map_err(|_| InlineDriveError::RejectedMsg(party_index))?;
                    progressed = true;
                } else {
                    return Ok(progressed);
                }
            }
            ProceedResult::Yielded => {
                progressed = true;
            }
            ProceedResult::Output(result) => match result {
                Ok(ok) => {
                    *completed = Some(ok);
                    return Ok(true);
                }
                Err(e) => {
                    return Err(InlineDriveError::ProtocolError(party_index, e.to_string()));
                }
            },
            ProceedResult::Error(e) => {
                return Err(InlineDriveError::SmError(party_index, e.to_string()));
            }
        }
    }
}
