//! Lightweight per-message proof-of-work (SPEC.md §8): not about content —
//! a relay/mailbox node never inspects what's inside a message, only
//! whether the sender paid a small CPU cost to send it. Invisible to a
//! normal user (a few milliseconds at low difficulty); expensive at the
//! scale a spam bot would need to operate at.
//!
//! Hashcash-style: find a `nonce` such that
//! `SHA-256(challenge_bytes || nonce)` has at least `difficulty_bits`
//! leading zero bits. `challenge_bytes` should bind to the specific
//! message (recipient + ciphertext + timestamp) so a solved PoW can't be
//! replayed for a different message.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Challenge {
    pub bytes: Vec<u8>,
    pub difficulty_bits: u8,
}

/// Binds the challenge to this specific message so a solved PoW can't be
/// replayed to cover a different (or repeated) send.
pub fn challenge_for_message(
    recipient_key_hash: &[u8],
    message_ciphertext: &[u8],
    timestamp: i64,
    difficulty_bits: u8,
) -> Challenge {
    let mut hasher = Sha256::new();
    hasher.update(recipient_key_hash);
    hasher.update(message_ciphertext);
    hasher.update(timestamp.to_be_bytes());
    Challenge {
        bytes: hasher.finalize().to_vec(),
        difficulty_bits,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Solution {
    pub nonce: u64,
}

fn attempt_hash(challenge_bytes: &[u8], nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge_bytes);
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().into()
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut count = 0;
    for byte in hash {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

fn meets_difficulty(challenge_bytes: &[u8], nonce: u64, difficulty_bits: u8) -> bool {
    leading_zero_bits(&attempt_hash(challenge_bytes, nonce)) >= difficulty_bits as u32
}

/// Grinds nonces starting from 0 until one satisfies the challenge.
/// Expected work is `2^difficulty_bits` hashes — keep `difficulty_bits`
/// small (SPEC.md says "liviano"); this is meant to cost a legitimate
/// sender milliseconds, not seconds.
pub fn solve(challenge: &Challenge) -> Solution {
    let mut nonce: u64 = 0;
    loop {
        if meets_difficulty(&challenge.bytes, nonce, challenge.difficulty_bits) {
            return Solution { nonce };
        }
        nonce += 1;
    }
}

pub fn verify(challenge: &Challenge, solution: &Solution) -> bool {
    meets_difficulty(&challenge.bytes, solution.nonce, challenge.difficulty_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solved_proof_of_work_verifies() {
        let challenge = challenge_for_message(b"recipient", b"ciphertext", 1000, 12);
        let solution = solve(&challenge);
        assert!(verify(&challenge, &solution));
    }

    #[test]
    fn wrong_nonce_fails_verification() {
        let challenge = challenge_for_message(b"recipient", b"ciphertext", 1000, 12);
        let solution = solve(&challenge);
        let wrong = Solution {
            nonce: solution.nonce.wrapping_add(1),
        };
        // Overwhelmingly likely to fail — a random neighboring nonce
        // satisfying the same difficulty is a 1-in-4096 coincidence at
        // 12 bits, and if it ever does, that's still a valid PoW for this
        // challenge, so tolerate it rather than flake.
        if !verify(&challenge, &wrong) {
            // expected path
        } else {
            let farther_wrong = Solution {
                nonce: solution.nonce.wrapping_add(999_999),
            };
            assert!(!verify(&challenge, &farther_wrong));
        }
    }

    #[test]
    fn solution_does_not_transfer_to_a_different_message() {
        let challenge_a = challenge_for_message(b"recipient", b"message A", 1000, 12);
        let challenge_b = challenge_for_message(b"recipient", b"message B", 1000, 12);
        let solution_a = solve(&challenge_a);
        assert!(!verify(&challenge_b, &solution_a));
    }

    #[test]
    fn different_timestamps_prevent_replay_of_the_same_content() {
        let challenge_1 = challenge_for_message(b"recipient", b"same ciphertext", 1000, 8);
        let challenge_2 = challenge_for_message(b"recipient", b"same ciphertext", 2000, 8);
        assert_ne!(challenge_1.bytes, challenge_2.bytes);
    }

    #[test]
    fn higher_difficulty_solutions_still_verify_at_their_own_level() {
        let challenge = challenge_for_message(b"recipient", b"ciphertext", 1000, 16);
        let solution = solve(&challenge);
        assert!(verify(&challenge, &solution));
        // A solution meeting 16 bits of difficulty necessarily also meets
        // any lower difficulty threshold for the same challenge bytes.
        let lower = Challenge {
            bytes: challenge.bytes.clone(),
            difficulty_bits: 8,
        };
        assert!(verify(&lower, &solution));
    }
}
