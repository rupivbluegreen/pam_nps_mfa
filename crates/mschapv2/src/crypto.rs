//! RFC 2759 MSCHAPv2 math, verified against `TEST_VECTORS.md` §1
//! (RFC 2759 §9.2).
//!
//! Security posture (CLAUDE.md hard rules):
//! - md4 and single DES are intentionally weak primitives that MSCHAPv2
//!   mandates (rule 9). They are not "upgraded" or removed.
//! - The NT hash and the derived 8-octet DES keys are password-equivalent, so
//!   every internal copy lives in `zeroize::Zeroizing` and is wiped on drop
//!   (rule 8). The public `[u8; 16]` / `[u8; 24]` returns are unavoidable per
//!   the fixed vector signatures, but no extra copies are kept alive here.
//! - The Success-authenticator comparison is constant time via `subtle`
//!   (rule 6/7); the string form is hex-decoded before comparison so a naive
//!   `==` never leaks length or case.

use des::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use des::Des;
use md4::Md4;
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// RFC 2759 §8.7 signing constant (39 octets).
const MAGIC1: &[u8] = b"Magic server to client signing constant";
/// RFC 2759 §8.7 padding constant (41 octets).
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";

/// `NtPasswordHash = MD4( password encoded UTF-16LE )` (RFC 2759 §8.3).
///
/// The password is encoded little-endian per UTF-16 code unit. The transient
/// UTF-16LE buffer is password-equivalent and is wiped on drop.
pub fn nt_password_hash(password: &str) -> [u8; 16] {
    let utf16le: Zeroizing<Vec<u8>> =
        Zeroizing::new(password.encode_utf16().flat_map(u16::to_le_bytes).collect());
    md4_16(&utf16le)
}

/// `PasswordHashHash = MD4( the raw 16 NT-hash octets )` (RFC 2759 §8.5).
///
/// This is MD4 *of bytes*, NOT of a UTF-16 string — the classic bug is running
/// the UTF-16 path here (TEST_VECTORS.md §1).
pub fn password_hash_hash(nt_hash: &[u8; 16]) -> [u8; 16] {
    md4_16(nt_hash)
}

/// `ChallengeHash = first 8 octets of SHA1( PeerChallenge ++
/// AuthenticatorChallenge ++ username )` (RFC 2759 §8.2).
///
/// Order matters. The username is the raw bytes here (NOT UTF-16), and in a
/// real deployment must be byte-identical to the User-Name attribute you send
/// (see [`crate::build_request`] and IMPLEMENTATION_SPEC.md §5).
pub fn challenge_hash(peer: &[u8; 16], auth: &[u8; 16], username: &[u8]) -> [u8; 8] {
    let mut sha = Sha1::new();
    sha.update(peer);
    sha.update(auth);
    sha.update(username);
    let digest = sha.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// `NtResponse` (RFC 2759 §8.1): the 24-octet challenge response.
///
/// Zero-pads the 16-octet NT hash to 21 octets, splits into three 7-octet
/// groups, expands each to an 8-octet DES key, and DES-encrypts the
/// 8-octet ChallengeHash under each key; the three blocks concatenate to 24
/// octets. The NT hash, the padded buffer, and the DES keys are all wiped on
/// drop.
pub fn generate_nt_response(
    auth: &[u8; 16],
    peer: &[u8; 16],
    username: &[u8],
    password: &str,
) -> [u8; 24] {
    let challenge = challenge_hash(peer, auth, username);
    let nt_hash = Zeroizing::new(nt_password_hash(password));
    challenge_response(&challenge, &nt_hash)
}

/// `AuthenticatorResponse` (RFC 2759 §8.7): the server-signing value the
/// client recomputes to mutually authenticate the server.
///
/// Returns `"S=" + UPPERCASE hex of the 20-byte digest` (40 hex chars). The NT
/// hash and its hash are wiped on drop.
pub fn generate_authenticator_response(
    password: &str,
    nt_response: &[u8; 24],
    peer: &[u8; 16],
    auth: &[u8; 16],
    username: &[u8],
) -> String {
    let password_hash = Zeroizing::new(nt_password_hash(password));
    let password_hash_hash = Zeroizing::new(password_hash_hash(&password_hash));

    // Digest = SHA1( PasswordHashHash ++ NtResponse ++ Magic1 )
    let mut sha = Sha1::new();
    sha.update(password_hash_hash.as_slice());
    sha.update(nt_response);
    sha.update(MAGIC1);
    let digest1 = sha.finalize();

    // Digest = SHA1( Digest ++ ChallengeHash ++ Magic2 )
    let challenge = challenge_hash(peer, auth, username);
    let mut sha = Sha1::new();
    sha.update(digest1);
    sha.update(challenge);
    sha.update(MAGIC2);
    let digest2 = sha.finalize();

    let mut out = String::with_capacity(42);
    out.push_str("S=");
    push_upper_hex(&mut out, &digest2);
    out
}

/// Verify a server `AuthenticatorResponse` against the locally computed one,
/// in constant time (CLAUDE.md rule 6/7).
///
/// Both `"S=..."` strings are hex-decoded to 20 octets and compared with
/// `subtle::ConstantTimeEq`, so a plain `==` never leaks length or case.
/// Returns `false` (deny) on ANY parse problem, and a Success-authenticator
/// mismatch denies the login even on an Access-Accept.
pub fn verify_authenticator_response(expected: &str, received: &str) -> bool {
    let a = match decode_s_value(expected) {
        Some(v) => v,
        None => return false,
    };
    let b = match decode_s_value(received) {
        Some(v) => v,
        None => return false,
    };
    bool::from(a.ct_eq(&b))
}

/// MD4 of a byte slice into a fixed 16-octet array.
fn md4_16(bytes: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(bytes);
    let mut digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    // The finalize output is an extra copy of password-equivalent material on
    // the NT-hash / password-hash-hash paths; wipe it before it drops (rule 8).
    digest.as_mut_slice().zeroize();
    out
}

/// The three-DES challenge response over an 8-octet challenge under the NT
/// hash (RFC 2759 §8.1 `ChallengeResponse`). All intermediate key material is
/// zeroized on drop.
fn challenge_response(challenge: &[u8; 8], nt_hash: &[u8; 16]) -> [u8; 24] {
    // Zero-pad the 16-octet hash to 21 octets, then three 7-octet groups.
    let mut padded = Zeroizing::new([0u8; 21]);
    padded[..16].copy_from_slice(nt_hash);

    let mut out = [0u8; 24];
    for (group, block_out) in padded.chunks_exact(7).zip(out.chunks_exact_mut(8)) {
        let mut key7 = Zeroizing::new([0u8; 7]);
        key7.copy_from_slice(group);
        let key8 = Zeroizing::new(expand_des_key(&key7));
        block_out.copy_from_slice(&des_encrypt_block(&key8, challenge));
    }
    out
}

/// Expand a 7-octet group into an 8-octet DES key (RFC 2759 §8.6 `DesEncrypt`
/// key spreading). Each output octet carries a 7-bit slice in its HIGH bits;
/// the low bit is parity and is ignored by DES.
fn expand_des_key(k: &[u8; 7]) -> [u8; 8] {
    [
        k[0] & 0xFE,
        (k[0] << 7) | (k[1] >> 1),
        (k[1] << 6) | (k[2] >> 2),
        (k[2] << 5) | (k[3] >> 3),
        (k[3] << 4) | (k[4] >> 4),
        (k[4] << 3) | (k[5] >> 5),
        (k[5] << 2) | (k[6] >> 6),
        k[6] << 1,
    ]
}

/// DES-encrypt a single 8-octet block under an 8-octet key. Uses the
/// re-exports under `des::cipher` to avoid a generic-array version mismatch
/// (IMPLEMENTATION_SPEC.md §2).
fn des_encrypt_block(key8: &[u8; 8], clear8: &[u8; 8]) -> [u8; 8] {
    let cipher = Des::new(GenericArray::from_slice(key8));
    let mut block = GenericArray::clone_from_slice(clear8);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(&block);
    out
}

/// Decode a `"S=" + 40 hex` authenticator-response string to its 20 octets.
/// Requires the `S=` prefix and EXACTLY 40 hexadecimal characters after it;
/// anything else returns `None` (deny).
fn decode_s_value(s: &str) -> Option<[u8; 20]> {
    let hex = s.strip_prefix("S=")?;
    if hex.len() != 40 {
        return None;
    }
    hex_decode_20(hex.as_bytes())
}

/// Decode exactly 40 ASCII hex octets into a 20-byte array, case-insensitive.
fn hex_decode_20(hex: &[u8]) -> Option<[u8; 20]> {
    if hex.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (byte, pair) in out.iter_mut().zip(hex.chunks_exact(2)) {
        *byte = (hex_val(pair[0])? << 4) | hex_val(pair[1])?;
    }
    Some(out)
}

/// A single ASCII hex digit to its 0..=15 value, or `None` if not hex.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Append the UPPERCASE hex of `bytes` to `out`.
fn push_upper_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0F)] as char);
    }
}
