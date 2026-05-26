//! MPC-Spec §05.4.6 / ADR-0051 index translation.
//!
//! The cggmp24 signing/presigning state machine identifies parties by their
//! 0-based POSITION within the signing subset (`0..t`). The canonical wire
//! (`from_party`/`to_party`) and peer routing are keyed by the ABSOLUTE keygen
//! party index — the entries of `parties_at_keygen`, the ascending cosigner set
//! fixed at DKG, which a BRC-52 cert lookup keys on (§05.6).
//!
//! `parties_at_keygen[position] == absolute`, so:
//! - **send:** translate SM-position → absolute before emitting on the wire.
//! - **receive:** translate absolute → SM-position before feeding the SM.
//!
//! For a contiguous subset (`{0,1}`) position == absolute and both are no-ops;
//! for a non-contiguous subset (`{0,2}`, where party 2 is position 1) the
//! translation is mandatory — omitting it mis-addresses every p2p message and
//! deadlocks the ceremony.
//!
//! Both the presign handler (`presign_handler.rs`) and the interactive signing
//! handler (`signing_handler.rs`) route by these helpers so the two paths
//! cannot drift apart again.

/// SM subset-position → absolute keygen party index. `None` if `pos` is outside
/// the subset (i.e. `>= parties_at_keygen.len()`).
pub(crate) fn pos_to_abs(parties_at_keygen: &[u16], pos: u16) -> Option<u16> {
    parties_at_keygen.get(pos as usize).copied()
}

/// Absolute keygen party index → SM subset-position. `None` if `abs` is not a
/// member of the signing subset.
pub(crate) fn abs_to_pos(parties_at_keygen: &[u16], abs: u16) -> Option<u16> {
    parties_at_keygen
        .iter()
        .position(|&p| p == abs)
        .map(|p| p as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contiguous_subset_is_identity() {
        let pak = [0u16, 1u16];
        for i in 0..2u16 {
            assert_eq!(pos_to_abs(&pak, i), Some(i));
            assert_eq!(abs_to_pos(&pak, i), Some(i));
        }
    }

    #[test]
    fn noncontiguous_subset_translates() {
        // Subset {0,2}: position 1 is the peer whose ABSOLUTE keygen index is 2.
        let pak = [0u16, 2u16];
        assert_eq!(pos_to_abs(&pak, 0), Some(0));
        assert_eq!(pos_to_abs(&pak, 1), Some(2));
        assert_eq!(abs_to_pos(&pak, 0), Some(0));
        assert_eq!(abs_to_pos(&pak, 2), Some(1));
    }

    #[test]
    fn round_trips_for_every_member() {
        let pak = [0u16, 2u16, 5u16];
        for (pos, &abs) in pak.iter().enumerate() {
            assert_eq!(pos_to_abs(&pak, pos as u16), Some(abs));
            assert_eq!(abs_to_pos(&pak, abs), Some(pos as u16));
        }
    }

    #[test]
    fn out_of_subset_is_none() {
        let pak = [0u16, 2u16];
        // absolute index 1 is NOT a member of {0,2}
        assert_eq!(abs_to_pos(&pak, 1), None);
        // position 2 is past the end of a 2-member subset
        assert_eq!(pos_to_abs(&pak, 2), None);
    }
}
