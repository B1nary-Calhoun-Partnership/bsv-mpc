//! #104 aux-reuse — the ADVERSARIAL NEGATIVE test set for the binding-envelope
//! load gate (`aux_binding::validate_aux_for_load`), security must-dos #5/#6/#7.
//!
//! Validate-don't-skip: every hostile aux MUST be rejected at LOAD for the RIGHT
//! reason (a specific `MpcError::AuxBindingRejected` message) — never a late,
//! opaque sign-time abort. The dangerous case is the COHERENT swap: a fully
//! self-consistent substitute aux (`N[i]==p*q` holds, so `from_parts` accepts it)
//! whose contributor knows the factorization. Only the signed/MAC'd envelope over
//! the recorded moduli defeats it — proven below.
//!
//! Run: `cargo test -p bsv-mpc-core --test aux_binding_neg -- --nocapture`

use std::collections::VecDeque;

use bsv_mpc_core::aux_binding::{
    aux_binding_mac, build_aux_binding_record, validate_aux_for_load, AuxLoadExpectation,
};
use bsv_mpc_core::canonical::AuxGroupDescriptor;
use bsv_mpc_core::MpcError;
use cggmp24::security_level::SecurityLevel128;
use cggmp24::ExecutionId;

// ──────────────────────────────────────────────────────────────────────────
// Buffered sink for the cggmp24 simulation (from the proven POCs).
// ──────────────────────────────────────────────────────────────────────────
#[pin_project::pin_project]
struct BufferedSink<M, Inner> {
    #[pin]
    messages: VecDeque<M>,
    #[pin]
    inner: Inner,
}
impl<M: Unpin, Inner: futures::Sink<M>> futures::Sink<M> for BufferedSink<M, Inner> {
    type Error = Inner::Error;
    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        while !self.messages.is_empty() {
            let mut projection = self.as_mut().project();
            let mut inner = projection.inner;
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = projection.messages.pop_front() {
                inner.as_mut().start_send(item)?;
            }
        }
        self.project().inner.poll_flush(cx)
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}
type BufferedDelivery<M, D> = (
    <D as round_based::Delivery<M>>::Receive,
    BufferedSink<round_based::Outgoing<M>, <D as round_based::Delivery<M>>::Send>,
);
fn buffer_outgoing<M, D, R>(
    party: round_based::MpcParty<M, D, R>,
) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
where
    M: Unpin,
    D: round_based::Delivery<M>,
    R: round_based::runtime::AsyncRuntime,
{
    party.map_delivery(|delivery| {
        let (incoming, outgoing) = delivery.split();
        (
            incoming,
            BufferedSink {
                messages: VecDeque::new(),
                inner: outgoing,
            },
        )
    })
}

fn generate_blum_prime(rng: &mut impl rand::RngCore, bits: u32) -> cggmp24::backend::Integer {
    use cggmp24::backend::Integer;
    loop {
        let n = Integer::generate_prime(rng, bits);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}
fn test_primes(
    rng: &mut impl rand::RngCore,
) -> cggmp24::key_refresh::PregeneratedPrimes<SecurityLevel128> {
    use cggmp24::security_level::SecurityLevel;
    let b = SecurityLevel128::RSA_PRIME_BITLEN;
    cggmp24::key_refresh::PregeneratedPrimes::try_from([
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
        generate_blum_prime(rng, b),
    ])
    .expect("primes have wrong bit size")
}

/// Fresh `aux_info_gen(n)` → each party's `AuxInfo` (each carries the FULL moduli
/// vectors). Independent generations produce independent moduli.
fn aux_gen(n: u16) -> Vec<cggmp24::key_share::AuxInfo<SecurityLevel128>> {
    let mut rng = rand::rngs::OsRng;
    let eid_bytes: [u8; 32] = rand::Rng::gen(&mut rng);
    let eid = ExecutionId::new(&eid_bytes);
    let primes: Vec<_> = (0..n).map(|_| test_primes(&mut rng)).collect();
    round_based::sim::run(n, |i, party| {
        let party = buffer_outgoing(party);
        let mut r = rand::rngs::OsRng;
        let pre = primes[usize::from(i)].clone();
        async move {
            cggmp24::aux_info_gen(eid, i, n, pre)
                .start(&mut r, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec()
}

fn descriptor(n: usize, tag: u8, t: u16) -> AuxGroupDescriptor {
    let masters: Vec<[u8; 33]> = (0..n)
        .map(|i| {
            let mut m = [0x02u8; 33];
            m[1] = tag;
            m[2] = i as u8;
            m
        })
        .collect();
    AuxGroupDescriptor {
        index_masters: masters,
        threshold: t,
        security_level_bits: 128,
    }
}

#[track_caller]
fn assert_rejected(result: Result<(), MpcError>, expect_substr: &str) {
    match result {
        Err(MpcError::AuxBindingRejected(msg)) => assert!(
            msg.contains(expect_substr),
            "rejected for the WRONG reason: got {msg:?}, expected substring {expect_substr:?}"
        ),
        other => panic!("expected AuxBindingRejected({expect_substr:?}), got {other:?}"),
    }
}

const KEY: [u8; 32] = [0x42u8; 32];
const EPOCH: u64 = 7;

/// The full adversarial set in one fixture (aux generation is the expensive
/// part, so two n=2 auxes + one n=3 aux are generated ONCE and reused).
#[test]
fn binding_gate_accepts_genuine_and_rejects_every_adversarial_aux() {
    let d = descriptor(2, 0xAA, 2);
    let aux_a = aux_gen(2); // the genuine group aux (vector shared by both parties)
    let aux_b = aux_gen(2); // an INDEPENDENT, internally-coherent substitute
    let record = build_aux_binding_record(&d, &aux_a[0], EPOCH).expect("build record");
    let mac = aux_binding_mac(&record, &KEY);
    let exp = AuxLoadExpectation::from_descriptor(&d, EPOCH);

    // ── POSITIVE: the genuine aux validates for BOTH party indices (the record
    //    is group-level — any party's aux carries the same moduli vector). ────
    validate_aux_for_load(&exp, 0, &aux_a[0], &record, &mac, &KEY)
        .expect("genuine aux for index 0 must validate");
    validate_aux_for_load(&exp, 1, &aux_a[1], &record, &mac, &KEY)
        .expect("genuine aux for index 1 must validate");

    // ── NEG: MAC mismatch (storage tamper / wrong at-rest key). ──────────────
    let mut bad_mac = mac;
    bad_mac[0] ^= 1;
    assert_rejected(
        validate_aux_for_load(&exp, 0, &aux_a[0], &record, &bad_mac, &KEY),
        "MAC mismatch",
    );
    assert_rejected(
        validate_aux_for_load(&exp, 0, &aux_a[0], &record, &mac, &[0x43u8; 32]),
        "MAC mismatch",
    );

    // ── NEG: wrong group (a rotated/different master ⇒ different group-id). ───
    let exp_rotated = AuxLoadExpectation::from_descriptor(&descriptor(2, 0xBB, 2), EPOCH);
    assert_rejected(
        validate_aux_for_load(&exp_rotated, 0, &aux_a[0], &record, &mac, &KEY),
        "group-id != current pinned group",
    );

    // ── NEG: stale aux-epoch (Notary rotated/reshared ⇒ must regenerate). ────
    let exp_stale = AuxLoadExpectation::from_descriptor(&d, EPOCH + 1);
    assert_rejected(
        validate_aux_for_load(&exp_stale, 0, &aux_a[0], &record, &mac, &KEY),
        "stale aux",
    );

    // ── NEG: COHERENT swap — the dangerous case. aux_b[0] is a fully valid,
    //    independent aux: `from_parts`' only modulus check (N[i]==p*q) PASSES,
    //    yet it is NOT the recorded aux. The envelope catches it at the digest. ─
    {
        use cggmp24::backend::Integer;
        let prod: Integer = &aux_b[0].p * &aux_b[0].q;
        assert_eq!(
            aux_b[0].N[0], prod,
            "precondition: the substitute aux is internally coherent, so from_parts ALONE accepts it"
        );
    }
    assert_rejected(
        validate_aux_for_load(&exp, 0, &aux_b[0], &record, &mac, &KEY),
        "N[0] != recorded digest",
    );

    // ── NEG: wrong-index aux (party 0's aux loaded as if for index 1). The
    //    moduli VECTOR matches the record (same aux), so the digest checks pass
    //    and it reaches the explicit from_parts identity (#7): aux.N[1] is p1*q1
    //    but this aux's (p,q) are p0,q0 ⇒ N[1] != p*q ⇒ rejected as wrong-index. ─
    assert_rejected(
        validate_aux_for_load(&exp, 1, &aux_a[0], &record, &mac, &KEY),
        "wrong-index aux",
    );

    // ── NEG: duplicate modulus across two indices (a Notary reusing one key).
    //    Craft a self-consistent aux+record whose slot 1 duplicates slot 0, so
    //    only the distinctness check (#6) can catch it. ───────────────────────
    let dup_aux = make_duplicate_modulus_aux(&aux_a[0]);
    let dup_record = build_aux_binding_record(&d, &dup_aux, EPOCH).expect("dup record");
    let dup_mac = aux_binding_mac(&dup_record, &KEY);
    assert_rejected(
        validate_aux_for_load(&exp, 0, &dup_aux, &dup_record, &dup_mac, &KEY),
        "duplicate Paillier modulus at index 1",
    );

    // ── NEG: n-mismatch — an aux with a different number of parties (here n=3
    //    loaded into the n=2 group) is rejected at the structural shape check. ─
    let aux_n3 = aux_gen(3);
    assert_rejected(
        validate_aux_for_load(&exp, 0, &aux_n3[0], &record, &mac, &KEY),
        "aux vector length",
    );

    // ── NEG: tampered binding record (a single digest flipped) ⇒ MAC fails
    //    before any modulus comparison runs (defense ordering). ───────────────
    let mut tampered_record = record.clone();
    tampered_record.n_digests[1][0] ^= 1;
    assert_rejected(
        validate_aux_for_load(&exp, 0, &aux_a[0], &tampered_record, &mac, &KEY),
        "MAC mismatch",
    );

    eprintln!("✔ #104 binding gate: genuine aux accepted; swapped/stale/coherent/duplicate/n-mismatch/MAC-tamper all REJECTED at LOAD for the right reason");
}

/// Build a hostile aux whose slot-1 moduli DUPLICATE slot 0 (a Notary reusing one
/// Paillier key across two of its indices). Crafted via JSON so it still passes
/// the crate's `is_valid` (which checks gcd + bit-length but NOT distinctness).
fn make_duplicate_modulus_aux(
    aux: &cggmp24::key_share::AuxInfo<SecurityLevel128>,
) -> cggmp24::key_share::AuxInfo<SecurityLevel128> {
    let mut v: serde_json::Value = serde_json::to_value(aux).expect("aux to value");
    let n0 = v["N"][0].clone();
    v["N"][1] = n0;
    let ped0 = v["pedersen_params"][0].clone();
    v["pedersen_params"][1] = ped0;
    serde_json::from_value(v).expect("duplicate-modulus aux still passes crate is_valid")
}
