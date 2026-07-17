//! GCP Confidential Space implementation of [`AttestationVerifier`].
//!
//! A Confidential Space workload requests an attestation token from the TEE
//! launcher; Google's Confidential Computing service returns a signed RS256 JWT
//! whose claims describe the hardware and the exact workload that is running,
//! and whose `eat_nonce` claim echoes back a value the workload chose. Our
//! enclave sets that nonce to its channel public key, so verifying the token
//! proves the key belongs to a genuine enclave running the expected image.
//!
//! [`GcpConfidentialSpaceVerifier`] checks, all of which must hold:
//! - the JWT is signed by one of Google's published keys (RS256, by `kid`),
//! - `iss` is the Confidential Computing service and `aud`/`exp` are valid,
//! - `eat_nonce` equals the hex of the channel public key (the binding),
//! - `submods.container.image_digest` is the exact workload image we expect,
//! - `swname` is `CONFIDENTIAL_SPACE`, and in production the image is hardened
//!   (`dbgstat == "disabled"`).
//!
//! Signature keys are fetched once with [`fetch_google_signing_keys`] and held
//! in the verifier, so [`AttestationVerifier::verify`] stays synchronous and
//! does no I/O.

use super::confidential_inference::AttestationVerifier;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;

/// Issuer of a genuine Confidential Space attestation token.
const CS_ISSUER: &str = "https://confidentialcomputing.googleapis.com";
/// `swname` claim of a Confidential Space workload.
const CS_SWNAME: &str = "CONFIDENTIAL_SPACE";
/// `.well-known` document that points at Google's signing keys.
const CS_OIDC_CONFIG: &str =
    "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration";

/// The claims we read out of the token. Registered claims (`iss`, `aud`, `exp`,
/// `nbf`) are validated separately by [`Validation`]; this struct only carries
/// the Confidential Space fields we additionally check.
#[derive(Debug, Deserialize)]
struct CsClaims {
    /// Hex of the value the workload bound into the token — our channel pubkey.
    eat_nonce: String,
    /// Software running the workload; must be `CONFIDENTIAL_SPACE`.
    swname: String,
    /// `"enabled"` on a debug image, `"disabled"` on a hardened one.
    #[serde(default)]
    dbgstat: String,
    submods: Submods,
}

#[derive(Debug, Deserialize)]
struct Submods {
    container: ContainerClaims,
}

#[derive(Debug, Deserialize)]
struct ContainerClaims {
    /// The exact image the enclave ran, e.g. `sha256:…`.
    image_digest: String,
}

/// Verifies a GCP Confidential Space attestation token binds a channel public
/// key to a genuine enclave running the expected workload image.
pub struct GcpConfidentialSpaceVerifier {
    /// Google's signing keys, indexed by JWT `kid`.
    keys: HashMap<String, DecodingKey>,
    /// The audience the workload requested (and the token must carry).
    audience: String,
    /// The exact workload image digest (`sha256:…`) the enclave must be running.
    expected_image_digest: String,
    /// Require a hardened (non-debug) image. `false` accepts a debug image for
    /// development; production must set this `true`.
    require_production: bool,
}

impl GcpConfidentialSpaceVerifier {
    /// Build a verifier over pre-fetched Google signing `keys` (see
    /// [`fetch_google_signing_keys`]).
    pub fn new(
        keys: HashMap<String, DecodingKey>,
        audience: impl Into<String>,
        expected_image_digest: impl Into<String>,
        require_production: bool,
    ) -> Self {
        Self {
            keys,
            audience: audience.into(),
            expected_image_digest: expected_image_digest.into(),
            require_production,
        }
    }
}

impl AttestationVerifier for GcpConfidentialSpaceVerifier {
    fn verify(&self, attestation: &[u8], channel_pubkey: &[u8; 32]) -> bool {
        let Ok(token) = std::str::from_utf8(attestation) else {
            return false;
        };
        // Pick the signing key named by the token header.
        let Ok(header) = decode_header(token) else {
            return false;
        };
        let Some(kid) = header.kid else {
            return false;
        };
        let Some(key) = self.keys.get(&kid) else {
            return false;
        };

        // Verify signature + issuer + audience + expiry in one step.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[CS_ISSUER]);
        validation.set_audience(&[self.audience.as_str()]);
        let Ok(data) = decode::<CsClaims>(token, key, &validation) else {
            return false;
        };
        let claims = data.claims;

        // The binding: the token must vouch for exactly this channel key.
        if claims.eat_nonce.to_lowercase() != hex::encode(channel_pubkey) {
            return false;
        }
        // The enclave must be running exactly the workload we expect.
        if claims.submods.container.image_digest != self.expected_image_digest {
            return false;
        }
        if claims.swname != CS_SWNAME {
            return false;
        }
        // In production, refuse a debug image (its memory is inspectable).
        if self.require_production && claims.dbgstat != "disabled" {
            return false;
        }
        true
    }
}

/// Fetch Google's current Confidential Space signing keys, indexed by `kid`,
/// ready to build a [`GcpConfidentialSpaceVerifier`]. Refresh periodically —
/// Google rotates the keys.
pub async fn fetch_google_signing_keys() -> anyhow::Result<HashMap<String, DecodingKey>> {
    #[derive(Deserialize)]
    struct Oidc {
        jwks_uri: String,
    }
    let oidc: Oidc = reqwest::get(CS_OIDC_CONFIG).await?.json().await?;
    let jwks: jsonwebtoken::jwk::JwkSet = reqwest::get(&oidc.jwks_uri).await?.json().await?;

    let mut keys = HashMap::new();
    for jwk in &jwks.keys {
        if let Some(kid) = jwk.common.key_id.clone() {
            if let Ok(key) = DecodingKey::from_jwk(jwk) {
                keys.insert(kid, key);
            }
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    // Throwaway 2048-bit RSA keypair — stands in for Google's signing key so the
    // full verify path (signature + claims) runs offline and deterministically.
    const TEST_PRIV: &str = include_str!("test_data/attestation_test_priv.pem");
    const TEST_PUB: &str = include_str!("test_data/attestation_test_pub.pem");
    const TEST_KID: &str = "test-key-1";
    const AUDIENCE: &str = "paraloom-inference";
    const IMAGE: &str = "sha256:6a4befe4704293205319d219ec3bb81ca6abe4e3e88d45ab973c2aaee60ae8aa";

    #[derive(Serialize)]
    struct TestContainer {
        image_digest: String,
    }
    #[derive(Serialize)]
    struct TestSubmods {
        container: TestContainer,
    }
    #[derive(Serialize)]
    struct TestToken {
        iss: String,
        aud: String,
        exp: usize,
        eat_nonce: String,
        swname: String,
        dbgstat: String,
        submods: TestSubmods,
    }

    fn pubkey() -> [u8; 32] {
        [7u8; 32]
    }

    /// Build a token with the given tweaks applied, signed by the test key.
    fn signed_token(mut edit: impl FnMut(&mut TestToken)) -> String {
        let mut claims = TestToken {
            iss: CS_ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            exp: 4_102_444_800, // year 2100
            eat_nonce: hex::encode(pubkey()),
            swname: CS_SWNAME.to_string(),
            dbgstat: "disabled".to_string(),
            submods: TestSubmods {
                container: TestContainer {
                    image_digest: IMAGE.to_string(),
                },
            },
        };
        edit(&mut claims);
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(TEST_PRIV.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn verifier(require_production: bool) -> GcpConfidentialSpaceVerifier {
        let mut keys = HashMap::new();
        keys.insert(
            TEST_KID.to_string(),
            DecodingKey::from_rsa_pem(TEST_PUB.as_bytes()).unwrap(),
        );
        GcpConfidentialSpaceVerifier::new(keys, AUDIENCE, IMAGE, require_production)
    }

    #[test]
    fn accepts_a_well_formed_token_bound_to_the_key() {
        let token = signed_token(|_| {});
        assert!(verifier(true).verify(token.as_bytes(), &pubkey()));
    }

    #[test]
    fn rejects_a_token_bound_to_a_different_key() {
        let token = signed_token(|_| {});
        // Same token, but checked against a different channel key.
        assert!(!verifier(true).verify(token.as_bytes(), &[9u8; 32]));
    }

    #[test]
    fn rejects_a_wrong_workload_image() {
        let token = signed_token(|t| t.submods.container.image_digest = "sha256:deadbeef".into());
        assert!(!verifier(true).verify(token.as_bytes(), &pubkey()));
    }

    #[test]
    fn rejects_a_non_confidential_space_token() {
        let token = signed_token(|t| t.swname = "SOMETHING_ELSE".into());
        assert!(!verifier(true).verify(token.as_bytes(), &pubkey()));
    }

    #[test]
    fn rejects_the_wrong_issuer_or_audience() {
        let bad_iss = signed_token(|t| t.iss = "https://evil.example".into());
        assert!(!verifier(true).verify(bad_iss.as_bytes(), &pubkey()));
        let bad_aud = signed_token(|t| t.aud = "someone-else".into());
        assert!(!verifier(true).verify(bad_aud.as_bytes(), &pubkey()));
    }

    #[test]
    fn rejects_an_expired_token() {
        let token = signed_token(|t| t.exp = 1_000_000_000); // year 2001
        assert!(!verifier(true).verify(token.as_bytes(), &pubkey()));
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let token = signed_token(|_| {});
        // Flip a character in the middle of the signature segment (the last
        // character only carries padding bits and may not change the bytes).
        let (rest, sig) = token.rsplit_once('.').unwrap();
        let mut sig: Vec<char> = sig.chars().collect();
        let mid = sig.len() / 2;
        sig[mid] = if sig[mid] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{}.{}", rest, sig.into_iter().collect::<String>());
        assert!(!verifier(true).verify(tampered.as_bytes(), &pubkey()));
    }

    #[test]
    fn production_verifier_rejects_a_debug_image() {
        let debug_token = signed_token(|t| t.dbgstat = "enabled".into());
        // Rejected in production...
        assert!(!verifier(true).verify(debug_token.as_bytes(), &pubkey()));
        // ...but accepted by a dev verifier that does not require hardening.
        assert!(verifier(false).verify(debug_token.as_bytes(), &pubkey()));
    }

    #[test]
    fn rejects_a_token_signed_by_an_unknown_key() {
        // A verifier whose key map does not contain the token's kid.
        let token = signed_token(|_| {});
        let empty = GcpConfidentialSpaceVerifier::new(HashMap::new(), AUDIENCE, IMAGE, true);
        assert!(!empty.verify(token.as_bytes(), &pubkey()));
    }
}
