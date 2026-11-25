//! Concat KDF for ECDH key agreement (RFC 7518 §4.6.2): the single-step KDF of NIST SP 800-56A
//! §5.8.1 with SHA-256, in the Direct Key Agreement form used by `ECDH-ES`.
//!
//! Round `i` (from 1) hashes `counter_i || Z || OtherInfo`, where
//! `OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo || SuppPrivInfo` and
//! * AlgorithmID = `len32(enc) || enc` (Direct Key Agreement: the `enc` value, not `alg`),
//! * PartyUInfo / PartyVInfo = `len32(data) || data`, data = base64url-decoded `apu` / `apv`,
//!   or empty with length 0 when absent,
//! * SuppPubInfo = keydatalen in bits as a 32-bit big-endian integer,
//! * SuppPrivInfo = the empty octet sequence.
//!
//! The first keydatalen bits of the concatenated round outputs are the key. For A128GCM and
//! A256GCM one SHA-256 round suffices.

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// SHA-256 output length in bytes (the Concat KDF hash length, RFC 7518 §4.6.2 "SHA-256").
const SHA256_OUTPUT_LEN: usize = 32;

/// Derives `key_len` bytes from `z`. `algorithm_id`, `apu` and `apv` are the raw Data parts;
/// this function adds their length prefixes.
pub(crate) fn concat_kdf(
    z: &[u8],
    algorithm_id: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_len: usize,
) -> Zeroizing<Vec<u8>> {
    let keydatalen_bits = len32(key_len * u8::BITS as usize);
    let rounds = key_len.div_ceil(SHA256_OUTPUT_LEN);
    let mut key = Zeroizing::new(Vec::with_capacity(rounds * SHA256_OUTPUT_LEN));
    for round in 1..=rounds {
        let mut hash = Sha256::new();
        hash.update(len32(round));
        hash.update(z);
        for data in [algorithm_id, apu, apv] {
            hash.update(len32(data.len()));
            hash.update(data);
        }
        hash.update(keydatalen_bits);
        // SuppPrivInfo is empty.
        let mut digest = hash.finalize();
        key.extend_from_slice(&digest);
        zeroize::Zeroize::zeroize(digest.as_mut_slice());
    }
    key.truncate(key_len);
    key
}

/// A 32-bit big-endian length or counter (RFC 7518 §4.6.2 "Datalen", SuppPubInfo). On the
/// Verifier path every input is bounded by [`crate::MAX_PROTECTED_HEADER_LEN`] (`apu`, `apv`) or
/// is a fixed key length, far below `u32::MAX`.
fn len32(n: usize) -> [u8; 4] {
    u32::try_from(n)
        .expect("Concat KDF inputs are bounded far below 2^32 bytes")
        .to_be_bytes()
}
