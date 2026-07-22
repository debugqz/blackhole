//! Crypto payment address *format* validation for in-chat payment requests
//! (SPEC.md §12/§15). This only rejects addresses that are structurally
//! impossible for the chosen asset — wrong length, bad charset, failed
//! checksum — to catch a mis-paste/typo before it's turned into a QR code
//! someone might actually pay. It is not, and cannot be, proof that the
//! address is controlled by whoever sent it; that's a social-trust problem
//! E2EE + safety-number verification already covers for the *channel*, not
//! for what's typed into it (see docs/THREAT_MODEL.md).
//!
//! Checksum verification here (Bitcoin's double-SHA256, Monero's
//! Keccak-256, Ethereum's EIP-55 mixed-case Keccak-256) is composition of
//! audited hash functions to validate a public encoding, not a
//! cryptosystem — same posture as `safety_number.rs` (SPEC.md §2.2).

use sha3::{Digest, Keccak256};

use crate::CryptoError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asset {
    Xmr,
    Btc,
    Eth,
}

fn err(msg: &'static str) -> CryptoError {
    CryptoError::NotImplemented(msg)
}

pub fn validate_address(asset: Asset, address: &str) -> Result<(), CryptoError> {
    let address = address.trim();
    if address.is_empty() {
        return Err(err("payment: empty address"));
    }
    match asset {
        Asset::Btc => validate_btc(address),
        Asset::Eth => validate_eth(address),
        Asset::Xmr => validate_xmr(address),
    }
}

/// Rejects negative, zero, non-numeric, or malformed amounts. Deliberately
/// a plain decimal string, never parsed to `f64` — this is only ever a
/// display hint in the chat bubble, never used for on-chain arithmetic (no
/// wei/atomic-unit conversion happens anywhere in this feature).
pub fn validate_amount(amount: &str) -> Result<(), CryptoError> {
    let amount = amount.trim();
    if amount.is_empty() {
        return Err(err("payment: empty amount"));
    }
    let mut seen_dot = false;
    let mut seen_nonzero_digit = false;
    for c in amount.chars() {
        match c {
            '0' => {}
            '1'..='9' => seen_nonzero_digit = true,
            '.' if !seen_dot => seen_dot = true,
            _ => return Err(err("payment: malformed amount")),
        }
    }
    if !seen_nonzero_digit {
        return Err(err("payment: amount must be positive"));
    }
    Ok(())
}

// ---------------- Bitcoin ----------------

fn validate_btc(address: &str) -> Result<(), CryptoError> {
    if let Some(rest) = address
        .strip_prefix("bc1")
        .or_else(|| address.strip_prefix("tb1"))
    {
        let _ = rest;
        let (hrp, _data) =
            bech32::decode(address).map_err(|_| err("payment: invalid bech32 BTC address"))?;
        if hrp.as_str() != "bc" && hrp.as_str() != "tb" {
            return Err(err("payment: unexpected bech32 HRP for BTC"));
        }
        return Ok(());
    }

    if !(25..=34).contains(&address.len()) {
        return Err(err("payment: invalid BTC address length"));
    }
    let decoded = bs58::decode(address)
        .with_check(None)
        .into_vec()
        .map_err(|_| err("payment: invalid base58check BTC address"))?;
    // version byte (P2PKH=0x00, P2SH=0x05) + 20-byte hash.
    if decoded.len() != 21 || (decoded[0] != 0x00 && decoded[0] != 0x05) {
        return Err(err("payment: unrecognized BTC address version"));
    }
    Ok(())
}

// ---------------- Ethereum ----------------

fn validate_eth(address: &str) -> Result<(), CryptoError> {
    let hex_part = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .ok_or_else(|| err("payment: ETH address must start with 0x"))?;
    if hex_part.len() != 40 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err("payment: ETH address must be 40 hex digits"));
    }

    let all_lower = hex_part.chars().all(|c| !c.is_ascii_uppercase());
    let all_upper = hex_part.chars().all(|c| !c.is_ascii_lowercase());
    if all_lower || all_upper {
        // No checksum casing present — nothing further to verify.
        return Ok(());
    }

    // EIP-55: checksum-case the lowercase hex against the Keccak-256 hash
    // of the lowercase address, and require it to match byte-for-byte.
    let lower = hex_part.to_ascii_lowercase();
    let hash = Keccak256::digest(lower.as_bytes());
    for (i, c) in lower.chars().enumerate() {
        if !c.is_ascii_alphabetic() {
            continue;
        }
        let nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        let should_be_upper = nibble >= 8;
        let actual_is_upper = hex_part.as_bytes()[i].is_ascii_uppercase();
        if should_be_upper != actual_is_upper {
            return Err(err("payment: ETH EIP-55 checksum mismatch"));
        }
    }
    Ok(())
}

// ---------------- Monero ----------------
//
// Monero addresses use a block-wise base58 encoding (not the "big integer"
// base58 Bitcoin uses): 8 raw bytes -> 11 base58 chars per full block, with
// a final partial block per a fixed size table. Decoded layout is
// `network_byte || 32-byte spend key || 32-byte view key || 4-byte
// checksum` (69 bytes) for standard/subaddress, or with an extra 8-byte
// payment id before the checksum (77 bytes) for integrated addresses.
// Checksum is the first 4 bytes of Keccak-256 over everything before it.

const MONERO_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const FULL_BLOCK_SIZE: usize = 8;
const FULL_ENCODED_BLOCK_SIZE: usize = 11;
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

// Mainnet network bytes: 18 = standard address, 19 = integrated address,
// 42 = subaddress. Testnet/stagenet are out of scope for a consumer app.
const MAINNET_STANDARD: u8 = 18;
const MAINNET_INTEGRATED: u8 = 19;
const MAINNET_SUBADDRESS: u8 = 42;

fn monero_alphabet_index(c: u8) -> Option<u64> {
    MONERO_ALPHABET
        .iter()
        .position(|&a| a == c)
        .map(|i| i as u64)
}

fn decoded_block_size(encoded_len: usize) -> Option<usize> {
    ENCODED_BLOCK_SIZES.iter().position(|&s| s == encoded_len)
}

fn decode_block(encoded: &[u8], raw_size: usize) -> Option<Vec<u8>> {
    let mut output = vec![0u8; raw_size];
    for &c in encoded {
        let mut carry = monero_alphabet_index(c)?;
        for byte in output.iter_mut().rev() {
            carry += (*byte as u64) * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        if carry != 0 {
            // Value doesn't fit in `raw_size` bytes — malformed block.
            return None;
        }
    }
    Some(output)
}

fn monero_base58_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(|&b| MONERO_ALPHABET.contains(&b)) {
        return None;
    }
    let full_blocks = bytes.len() / FULL_ENCODED_BLOCK_SIZE;
    let remainder_len = bytes.len() % FULL_ENCODED_BLOCK_SIZE;
    let remainder_raw_size = if remainder_len == 0 {
        0
    } else {
        decoded_block_size(remainder_len)?
    };

    let mut out = Vec::with_capacity(full_blocks * FULL_BLOCK_SIZE + remainder_raw_size);
    for i in 0..full_blocks {
        let chunk = &bytes[i * FULL_ENCODED_BLOCK_SIZE..(i + 1) * FULL_ENCODED_BLOCK_SIZE];
        out.extend(decode_block(chunk, FULL_BLOCK_SIZE)?);
    }
    if remainder_len != 0 {
        let chunk = &bytes[full_blocks * FULL_ENCODED_BLOCK_SIZE..];
        out.extend(decode_block(chunk, remainder_raw_size)?);
    }
    Some(out)
}

fn validate_xmr(address: &str) -> Result<(), CryptoError> {
    let decoded =
        monero_base58_decode(address).ok_or_else(|| err("payment: invalid base58 XMR address"))?;
    if decoded.len() != 69 && decoded.len() != 77 {
        return Err(err("payment: invalid XMR address length"));
    }
    let (body, checksum) = decoded.split_at(decoded.len() - 4);
    let expected: [u8; 4] = Keccak256::digest(body)[..4].try_into().unwrap();
    if checksum != expected {
        return Err(err("payment: XMR address checksum mismatch"));
    }
    match (decoded[0], decoded.len()) {
        (MAINNET_STANDARD, 69) | (MAINNET_SUBADDRESS, 69) | (MAINNET_INTEGRATED, 77) => Ok(()),
        _ => Err(err("payment: unrecognized XMR address type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monero_base58_encode(data: &[u8]) -> String {
        fn encode_block(chunk: &[u8], out_len: usize) -> String {
            let mut num = chunk.to_vec();
            let mut digits: Vec<u8> = Vec::with_capacity(out_len);
            // Repeated divide-by-58 over the big-endian byte array; each
            // remainder is one base58 digit, least-significant first.
            loop {
                let mut remainder: u32 = 0;
                let mut any_nonzero = false;
                for byte in num.iter_mut() {
                    let acc = remainder * 256 + *byte as u32;
                    *byte = (acc / 58) as u8;
                    remainder = acc % 58;
                    if *byte != 0 {
                        any_nonzero = true;
                    }
                }
                digits.push(remainder as u8);
                if !any_nonzero {
                    break;
                }
            }
            // Left-pad with zero digits (appended here, before the
            // most-significant-first reversal below) up to `out_len`.
            while digits.len() < out_len {
                digits.push(0);
            }
            digits.reverse();
            digits
                .iter()
                .map(|&d| MONERO_ALPHABET[d as usize] as char)
                .collect()
        }

        let mut out = String::new();
        let full_blocks = data.len() / FULL_BLOCK_SIZE;
        for i in 0..full_blocks {
            let chunk = &data[i * FULL_BLOCK_SIZE..(i + 1) * FULL_BLOCK_SIZE];
            out.push_str(&encode_block(chunk, FULL_ENCODED_BLOCK_SIZE));
        }
        let rem = &data[full_blocks * FULL_BLOCK_SIZE..];
        if !rem.is_empty() {
            let out_len = ENCODED_BLOCK_SIZES[rem.len()];
            out.push_str(&encode_block(rem, out_len));
        }
        out
    }

    fn make_valid_xmr(network_byte: u8, total_len: usize) -> String {
        let mut body = vec![network_byte];
        body.extend(vec![0xABu8; total_len - 1 - 4]);
        let checksum = &Keccak256::digest(&body)[..4];
        body.extend_from_slice(checksum);
        monero_base58_encode(&body)
    }

    #[test]
    fn monero_base58_roundtrips_arbitrary_bytes() {
        for len in [1usize, 4, 8, 9, 15, 16, 32, 69] {
            let data: Vec<u8> = (0..len as u8).collect();
            let encoded = monero_base58_encode(&data);
            let decoded = monero_base58_decode(&encoded).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for len {len}");
        }
    }

    #[test]
    fn valid_xmr_standard_address_is_accepted() {
        let addr = make_valid_xmr(MAINNET_STANDARD, 69);
        assert!(validate_address(Asset::Xmr, &addr).is_ok());
    }

    #[test]
    fn valid_xmr_integrated_address_is_accepted() {
        let addr = make_valid_xmr(MAINNET_INTEGRATED, 77);
        assert!(validate_address(Asset::Xmr, &addr).is_ok());
    }

    #[test]
    fn xmr_address_with_corrupted_checksum_is_rejected() {
        let mut addr = make_valid_xmr(MAINNET_STANDARD, 69);
        // Flip the last character to something else in the alphabet.
        let last = addr.pop().unwrap();
        let alt = MONERO_ALPHABET
            .iter()
            .map(|&b| b as char)
            .find(|&c| c != last)
            .unwrap();
        addr.push(alt);
        assert!(validate_address(Asset::Xmr, &addr).is_err());
    }

    #[test]
    fn xmr_unrecognized_network_byte_is_rejected() {
        let addr = make_valid_xmr(0x99, 69);
        assert!(validate_address(Asset::Xmr, &addr).is_err());
    }

    #[test]
    fn eth_lowercase_address_is_accepted_without_checksum() {
        assert!(validate_address(Asset::Eth, "0x0000000000000000000000000000000000000000").is_ok());
    }

    #[test]
    fn eth_wrong_length_is_rejected() {
        assert!(validate_address(Asset::Eth, "0x1234").is_err());
    }

    #[test]
    fn eth_missing_prefix_is_rejected() {
        assert!(validate_address(Asset::Eth, "0000000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn eth_valid_eip55_checksum_is_accepted() {
        // Derive a validly-checksummed address from an all-lowercase one
        // using the same algorithm under test, then confirm it verifies —
        // avoids depending on a memorized external test vector.
        let lower = "000102030405060708090a0b0c0d0e0f10111213";
        let hash = Keccak256::digest(lower.as_bytes());
        let mut checksummed = String::new();
        for (i, c) in lower.chars().enumerate() {
            let nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 0x0f
            };
            if c.is_ascii_alphabetic() && nibble >= 8 {
                checksummed.push(c.to_ascii_uppercase());
            } else {
                checksummed.push(c);
            }
        }
        let address = format!("0x{checksummed}");
        assert!(validate_address(Asset::Eth, &address).is_ok());
    }

    #[test]
    fn eth_broken_eip55_checksum_is_rejected() {
        let lower = "000102030405060708090a0b0c0d0e0f10111213";
        let hash = Keccak256::digest(lower.as_bytes());
        let mut checksummed = String::new();
        for (i, c) in lower.chars().enumerate() {
            let nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 0x0f
            };
            if c.is_ascii_alphabetic() && nibble >= 8 {
                checksummed.push(c.to_ascii_uppercase());
            } else {
                checksummed.push(c);
            }
        }
        // Flip the case of the first alphabetic character, breaking the checksum.
        let mut chars: Vec<char> = checksummed.chars().collect();
        let idx = chars.iter().position(|c| c.is_ascii_alphabetic()).unwrap();
        chars[idx] = if chars[idx].is_ascii_uppercase() {
            chars[idx].to_ascii_lowercase()
        } else {
            chars[idx].to_ascii_uppercase()
        };
        let address = format!("0x{}", chars.into_iter().collect::<String>());
        assert!(validate_address(Asset::Eth, &address).is_err());
    }

    #[test]
    fn btc_p2pkh_roundtrip_via_bs58_check_is_accepted() {
        let mut payload = vec![0x00u8];
        payload.extend(vec![0x11u8; 20]);
        let address = bs58::encode(&payload).with_check().into_string();
        assert!(validate_address(Asset::Btc, &address).is_ok());
    }

    #[test]
    fn btc_p2sh_roundtrip_via_bs58_check_is_accepted() {
        let mut payload = vec![0x05u8];
        payload.extend(vec![0x22u8; 20]);
        let address = bs58::encode(&payload).with_check().into_string();
        assert!(validate_address(Asset::Btc, &address).is_ok());
    }

    #[test]
    fn btc_bad_checksum_is_rejected() {
        let mut payload = vec![0x00u8];
        payload.extend(vec![0x11u8; 20]);
        let mut address = bs58::encode(&payload).with_check().into_string();
        let last = address.pop().unwrap();
        // Same base58 alphabet Bitcoin uses (identical to Monero's).
        let alt = MONERO_ALPHABET
            .iter()
            .map(|&b| b as char)
            .find(|&c| c != last)
            .unwrap();
        address.push(alt);
        assert!(validate_address(Asset::Btc, &address).is_err());
    }

    #[test]
    fn btc_bech32_mainnet_is_accepted() {
        let hrp = bech32::Hrp::parse("bc").unwrap();
        let data = vec![0u8; 20];
        let address = bech32::encode::<bech32::Bech32>(hrp, &data).unwrap();
        assert!(validate_address(Asset::Btc, &address).is_ok());
    }

    #[test]
    fn empty_address_is_rejected_for_every_asset() {
        for asset in [Asset::Xmr, Asset::Btc, Asset::Eth] {
            assert!(validate_address(asset, "").is_err());
            assert!(validate_address(asset, "   ").is_err());
        }
    }

    #[test]
    fn amount_validation() {
        assert!(validate_amount("1.5").is_ok());
        assert!(validate_amount("0.001").is_ok());
        assert!(validate_amount("100").is_ok());
        assert!(validate_amount("").is_err());
        assert!(validate_amount("0").is_err());
        assert!(validate_amount("0.0").is_err());
        assert!(validate_amount("-1").is_err());
        assert!(validate_amount("1.2.3").is_err());
        assert!(validate_amount("abc").is_err());
    }
}
