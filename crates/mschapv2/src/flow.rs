//! High-level MSCHAPv2 exchange helpers the PAM flow (phase 5) calls: generate
//! the challenges, build the request attributes, and verify the server's
//! Success from an Access-Accept.
//!
//! All state is local to one attempt (CLAUDE.md rule 17). A `getrandom`
//! failure denies (rule 18); there is no weak or zero fallback. Mutual auth is
//! mandatory: [`verify_access_accept`] denies unless the server's
//! MS-CHAP2-Success authenticator matches ours in constant time (rule 6).

use crate::crypto::{generate_authenticator_response, generate_nt_response};
use crate::vsa::{
    encode_ms_chap2_response, encode_ms_chap_challenge, find_ms_chap2_success,
    parse_ms_chap2_success,
};
use crate::RngError;

/// The two random 16-octet challenges for one MSCHAPv2 exchange. Both are sent
/// on the wire (the Authenticator Challenge in MS-CHAP-Challenge, the Peer
/// Challenge in MS-CHAP2-Response), so they are not secret, but they must be
/// fresh and unpredictable per attempt.
#[derive(Clone)]
pub struct Challenges {
    /// The Authenticator (NAS) Challenge — MS-CHAP-Challenge Data.
    pub authenticator_challenge: [u8; 16],
    /// The Peer (client) Challenge — part of the MS-CHAP2-Response Data.
    pub peer_challenge: [u8; 16],
}

/// Generate fresh Authenticator and Peer challenges from the OS CSPRNG.
///
/// Returns `Err(RngError)` if `getrandom` fails; the caller must deny
/// (CLAUDE.md rule 18). Never falls back to weak or zero material.
pub fn generate_challenges() -> Result<Challenges, RngError> {
    let mut authenticator_challenge = [0u8; 16];
    let mut peer_challenge = [0u8; 16];
    getrandom::getrandom(&mut authenticator_challenge).map_err(|_| RngError)?;
    getrandom::getrandom(&mut peer_challenge).map_err(|_| RngError)?;
    Ok(Challenges {
        authenticator_challenge,
        peer_challenge,
    })
}

/// The MSCHAPv2 attributes for one Access-Request, plus the expected server
/// authenticator response to check on the Access-Accept.
///
/// Deliberately implements neither `Debug` nor `Display`: the MS-CHAP2-Response
/// value carries the password-derived NT response (CLAUDE.md rule 3).
pub struct MsChapV2Request {
    ms_chap_challenge: Vec<u8>,
    ms_chap2_response: Vec<u8>,
    expected_authenticator: String,
}

impl MsChapV2Request {
    /// The MS-CHAP-Challenge Vendor-Specific *value*; pass to
    /// `radius::PacketBuilder::attribute(radius::attr::VENDOR_SPECIFIC, ..)`.
    pub fn ms_chap_challenge(&self) -> &[u8] {
        &self.ms_chap_challenge
    }

    /// The MS-CHAP2-Response Vendor-Specific *value*; pass to
    /// `radius::PacketBuilder::attribute(radius::attr::VENDOR_SPECIFIC, ..)`.
    pub fn ms_chap2_response(&self) -> &[u8] {
        &self.ms_chap2_response
    }

    /// The locally computed `"S=..."` authenticator response to verify the
    /// server's MS-CHAP2-Success against (mutual auth, rule 6).
    pub fn expected_authenticator(&self) -> &str {
        &self.expected_authenticator
    }
}

/// Build the MSCHAPv2 request attributes for one Access-Request.
///
/// Computes the NT response and the expected authenticator response from
/// `password` (the password is used only here and is not retained), then
/// encodes the MS-CHAP-Challenge and MS-CHAP2-Response Vendor-Specific values.
///
/// Username matching (IMPLEMENTATION_SPEC.md §5): `username` MUST be the exact
/// same byte string the caller places in the User-Name attribute. The
/// challenge hash and NPS both hash this string, so a domain-qualified vs. bare
/// mismatch (`DOMAIN\user` vs `user`) fails as if the password were wrong even
/// when it is correct. Pick one form and use it in BOTH places.
pub fn build_request(
    username: &[u8],
    password: &str,
    challenges: &Challenges,
    ident: u8,
) -> MsChapV2Request {
    let nt_response = generate_nt_response(
        &challenges.authenticator_challenge,
        &challenges.peer_challenge,
        username,
        password,
    );
    let expected_authenticator = generate_authenticator_response(
        password,
        &nt_response,
        &challenges.peer_challenge,
        &challenges.authenticator_challenge,
        username,
    );
    let ms_chap_challenge = encode_ms_chap_challenge(&challenges.authenticator_challenge);
    let ms_chap2_response =
        encode_ms_chap2_response(ident, &challenges.peer_challenge, &nt_response);

    MsChapV2Request {
        ms_chap_challenge,
        ms_chap2_response,
        expected_authenticator,
    }
}

/// Verify a server MS-CHAP2-Success Data field against the locally computed
/// `expected_authenticator`, in constant time.
///
/// `success_vendor_data` is the Data of the Vendor-Specific attribute with
/// Vendor-Id 311 and Vendor-Type 26. Returns `true` only on a match; a parse
/// defect or a mismatch returns `false` (deny even on an Access-Accept).
pub fn verify_success(expected_authenticator: &str, success_vendor_data: &[u8]) -> bool {
    match parse_ms_chap2_success(success_vendor_data) {
        Ok(received) => {
            crate::verify_authenticator_response(expected_authenticator, &received)
        }
        Err(_) => false,
    }
}

/// Verify the server's MS-CHAP2-Success from a parsed Access-Accept (mutual
/// authentication, CLAUDE.md rule 6).
///
/// Returns `true` only if the response carries an MS-CHAP2-Success whose `S=`
/// authenticator matches `expected_authenticator` in constant time. If the
/// Access-Accept carries NO MS-CHAP2-Success, this DENIES — an Accept without a
/// verifiable Success is the impersonation gap the module must not accept.
pub fn verify_access_accept(
    response: &radius::ParsedResponse<'_>,
    expected_authenticator: &str,
) -> bool {
    match find_ms_chap2_success(response) {
        Some(data) => verify_success(expected_authenticator, data),
        None => false,
    }
}
