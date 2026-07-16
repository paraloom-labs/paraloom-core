//! Attestation-bound sealed channel for confidential inference.
//!
//! The guarantee the confidential-AI layer is built toward is that the machine
//! running a model cannot read the prompt. Sealing the input to the owner
//! (`private_job`) is not enough on its own: to run the model, a worker must
//! decrypt the input, so a plaintext-executing worker still sees it. Closing
//! that gap needs the model to run inside a trusted execution environment
//! (TEE), and the client needs a way to send the prompt so that *only* a
//! genuine enclave — running the expected code — can open it.
//!
//! The cryptographic heart of that is an **attestation-bound sealed channel**:
//!
//! 1. The enclave generates a fresh X25519 keypair ([`EnclaveChannel`]).
//! 2. Its public key is carried inside the enclave's attestation report, so the
//!    key is cryptographically vouched for by the TEE hardware.
//! 3. A client verifies the attestation ([`AttestedChannelKey::verify`]) and,
//!    only if it vouches for the key, seals the prompt to it with the same
//!    `crypto_box` primitive the shielded stack uses.
//! 4. Only the enclave, holding the ephemeral secret, can open it.
//!
//! The attestation **report format is platform-specific** (GCP Confidential
//! Space, AMD SEV-SNP, Intel TDX, NVIDIA CC …). This module owns the channel
//! and the sealing; the report is verified through the [`AttestationVerifier`]
//! trait, whose concrete implementations land per platform.

use crate::privacy::note_crypto::{open, seal, EncryptedNote};
use crypto_box::{aead::OsRng, SecretKey};

/// The enclave side of a sealed channel: a fresh ephemeral X25519 keypair whose
/// public key is meant to be bound into the enclave's attestation report. The
/// secret never leaves the enclave.
pub struct EnclaveChannel {
    secret: [u8; 32],
    public: [u8; 32],
}

impl EnclaveChannel {
    /// Generate a fresh channel keypair. Call this once per enclave session so
    /// two sessions are unlinkable and a leaked key cannot open past prompts.
    pub fn generate() -> Self {
        let sk = SecretKey::generate(&mut OsRng);
        Self {
            public: *sk.public_key().as_bytes(),
            secret: sk.to_bytes(),
        }
    }

    /// The channel public key to publish inside the attestation report.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Open a prompt a client sealed to this channel. `None` on a wrong key or
    /// tampered ciphertext.
    pub fn open(&self, sealed: &EncryptedNote) -> Option<Vec<u8>> {
        open(&self.secret, sealed)
    }
}

/// An enclave channel public key together with the attestation report that
/// vouches for it. A client must never seal to `channel_pubkey` without first
/// verifying the attestation — that binding is the whole trust anchor.
#[derive(Clone, Debug)]
pub struct AttestedChannelKey {
    /// The X25519 public key the enclave will decrypt with.
    pub channel_pubkey: [u8; 32],
    /// The opaque, platform-specific attestation report vouching for the key.
    pub attestation: Vec<u8>,
}

impl AttestedChannelKey {
    /// Verify the attestation with `verifier` and return the key to seal to —
    /// but only if the report vouches for a genuine enclave, running the
    /// expected code, that holds exactly this `channel_pubkey`. Returns `None`
    /// when verification fails, so a caller can never accidentally seal to an
    /// unattested key.
    pub fn verify<V: AttestationVerifier>(&self, verifier: &V) -> Option<[u8; 32]> {
        if verifier.verify(&self.attestation, &self.channel_pubkey) {
            Some(self.channel_pubkey)
        } else {
            None
        }
    }
}

/// Verifies that a platform attestation report binds `channel_pubkey` to a
/// genuine enclave running the expected measurement. One implementation exists
/// per TEE platform; the report format lives entirely behind this trait.
pub trait AttestationVerifier {
    /// Return `true` only if `attestation` is a valid report from a genuine
    /// enclave running the expected code AND it binds exactly `channel_pubkey`.
    fn verify(&self, attestation: &[u8], channel_pubkey: &[u8; 32]) -> bool;
}

/// Seal `prompt` to a verified enclave channel. Returns `None` — never a
/// ciphertext — when the attestation does not vouch for the key, so a prompt is
/// only ever sealed to hardware that has proven it will stay blind.
pub fn seal_prompt<V: AttestationVerifier>(
    key: &AttestedChannelKey,
    verifier: &V,
    prompt: &[u8],
) -> Option<EncryptedNote> {
    let pubkey = key.verify(verifier)?;
    Some(seal(&pubkey, prompt))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test verifier that accepts one specific attestation blob and binds it to
    /// whatever key it carries — stands in for a real platform verifier so the
    /// channel/sealing logic can be exercised without a TEE.
    struct MockVerifier {
        accept: Vec<u8>,
    }
    impl AttestationVerifier for MockVerifier {
        fn verify(&self, attestation: &[u8], _channel_pubkey: &[u8; 32]) -> bool {
            attestation == self.accept.as_slice()
        }
    }

    fn attested(channel: &EnclaveChannel, report: &[u8]) -> AttestedChannelKey {
        AttestedChannelKey {
            channel_pubkey: channel.public_key(),
            attestation: report.to_vec(),
        }
    }

    #[test]
    fn prompt_sealed_to_a_verified_channel_round_trips() {
        let enclave = EnclaveChannel::generate();
        let key = attested(&enclave, b"good-report");
        let verifier = MockVerifier {
            accept: b"good-report".to_vec(),
        };

        let prompt = b"summarize this confidential document".to_vec();
        let sealed = seal_prompt(&key, &verifier, &prompt).expect("attestation accepted");
        assert_eq!(enclave.open(&sealed).expect("enclave opens"), prompt);
    }

    #[test]
    fn a_prompt_is_never_sealed_to_an_unverified_key() {
        let enclave = EnclaveChannel::generate();
        let key = attested(&enclave, b"forged-report");
        let verifier = MockVerifier {
            accept: b"good-report".to_vec(),
        };

        // The attestation does not verify, so nothing is sealed.
        assert!(seal_prompt(&key, &verifier, b"secret").is_none());
    }

    #[test]
    fn only_the_enclave_secret_opens_the_prompt() {
        let enclave = EnclaveChannel::generate();
        let other = EnclaveChannel::generate();
        let key = attested(&enclave, b"good-report");
        let verifier = MockVerifier {
            accept: b"good-report".to_vec(),
        };

        let sealed = seal_prompt(&key, &verifier, b"secret").expect("sealed");
        // A different enclave's secret cannot open it.
        assert!(other.open(&sealed).is_none());
        assert!(enclave.open(&sealed).is_some());
    }
}
