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
use anyhow::Result;
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

/// A model the enclave runs on an opened prompt. Kept behind a trait so the
/// channel and worker logic stay independent of the runtime (WASM, llama.cpp,
/// an accelerator) and of the model itself — confidential inference runs open
/// models, and which one is a deployment choice, not a protocol concern.
pub trait ModelRunner {
    /// Run the model on `prompt` and return its output. Runs inside the enclave,
    /// on plaintext that never leaves it.
    fn run(&self, prompt: &[u8]) -> Result<Vec<u8>>;
}

/// The plaintext a client seals to the enclave: the prompt, plus the key the
/// result must be sealed back to. Bundling the reply key inside the sealed
/// payload means the worker learns *both* only after decrypting inside the
/// enclave — it never sees the prompt or the recipient in the clear.
///
/// Encoding: `reply_to(32) || prompt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferencePayload {
    /// The prompt to run the model on.
    pub prompt: Vec<u8>,
    /// The X25519 public key the result is sealed to (the requester).
    pub reply_to: [u8; 32],
}

impl InferencePayload {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.prompt.len());
        out.extend_from_slice(&self.reply_to);
        out.extend_from_slice(&self.prompt);
        out
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 32 {
            return None;
        }
        let mut reply_to = [0u8; 32];
        reply_to.copy_from_slice(&b[..32]);
        Some(Self {
            reply_to,
            prompt: b[32..].to_vec(),
        })
    }
}

/// Seal an inference request — the prompt and the reply key — to a verified
/// enclave. Returns `None` (never a ciphertext) when the attestation does not
/// vouch for the key.
pub fn seal_request<V: AttestationVerifier>(
    key: &AttestedChannelKey,
    verifier: &V,
    payload: &InferencePayload,
) -> Option<EncryptedNote> {
    let pubkey = key.verify(verifier)?;
    Some(seal(&pubkey, &payload.to_bytes()))
}

/// The enclave side of confidential inference: an enclave channel plus a model.
/// [`handle`] opens a sealed request inside the enclave, runs the model, and
/// seals the result to the requester — the plaintext prompt and result never
/// leave the enclave.
///
/// [`handle`]: Self::handle
pub struct ConfidentialWorker<M: ModelRunner> {
    channel: EnclaveChannel,
    model: M,
}

impl<M: ModelRunner> ConfidentialWorker<M> {
    /// Build a worker over a freshly-generated enclave channel and a model.
    pub fn new(channel: EnclaveChannel, model: M) -> Self {
        Self { channel, model }
    }

    /// The channel public key to publish (bound into the attestation report) so
    /// clients can seal requests to this worker.
    pub fn channel_public_key(&self) -> [u8; 32] {
        self.channel.public_key()
    }

    /// Open a sealed request, run the model, and seal the result to the key the
    /// request named. Returns `Ok(None)` when the request cannot be opened
    /// (wrong key or malformed payload) — never plaintext. A model failure
    /// propagates as an error.
    pub fn handle(&self, sealed: &EncryptedNote) -> Result<Option<EncryptedNote>> {
        let Some(bytes) = self.channel.open(sealed) else {
            return Ok(None);
        };
        let Some(payload) = InferencePayload::from_bytes(&bytes) else {
            return Ok(None);
        };
        let result = self.model.run(&payload.prompt)?;
        Ok(Some(seal(&payload.reply_to, &result)))
    }
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

    /// Stand-in model: upper-cases the prompt so a test can check the worker ran
    /// the model on the real plaintext.
    struct UppercaseModel;
    impl ModelRunner for UppercaseModel {
        fn run(&self, prompt: &[u8]) -> Result<Vec<u8>> {
            Ok(prompt.to_ascii_uppercase())
        }
    }

    #[test]
    fn payload_round_trips_through_its_encoding() {
        let payload = InferencePayload {
            prompt: b"a prompt of some length".to_vec(),
            reply_to: [7u8; 32],
        };
        assert_eq!(
            InferencePayload::from_bytes(&payload.to_bytes()).unwrap(),
            payload
        );
        // Too short to hold the reply key.
        assert!(InferencePayload::from_bytes(&[0u8; 20]).is_none());
    }

    #[test]
    fn worker_runs_the_model_and_seals_the_result_to_the_requester() {
        // The requester's keypair; the result comes back sealed to its public key.
        let owner_sk = SecretKey::generate(&mut OsRng);
        let owner_pub = *owner_sk.public_key().as_bytes();

        let worker = ConfidentialWorker::new(EnclaveChannel::generate(), UppercaseModel);
        let key = AttestedChannelKey {
            channel_pubkey: worker.channel_public_key(),
            attestation: b"good-report".to_vec(),
        };
        let verifier = MockVerifier {
            accept: b"good-report".to_vec(),
        };

        let payload = InferencePayload {
            prompt: b"hello".to_vec(),
            reply_to: owner_pub,
        };
        let sealed_req = seal_request(&key, &verifier, &payload).expect("sealed");

        let sealed_res = worker
            .handle(&sealed_req)
            .expect("no model error")
            .expect("request handled");
        // Only the requester's secret opens the result.
        let result = open(&owner_sk.to_bytes(), &sealed_res).expect("owner opens result");
        assert_eq!(result, b"HELLO");
    }

    #[test]
    fn worker_rejects_a_request_sealed_to_a_different_enclave() {
        let owner_pub = *SecretKey::generate(&mut OsRng).public_key().as_bytes();
        let worker = ConfidentialWorker::new(EnclaveChannel::generate(), UppercaseModel);

        // Seal the request to some OTHER enclave's key, not this worker's.
        let other = EnclaveChannel::generate();
        let key = AttestedChannelKey {
            channel_pubkey: other.public_key(),
            attestation: b"good-report".to_vec(),
        };
        let verifier = MockVerifier {
            accept: b"good-report".to_vec(),
        };
        let sealed_req = seal_request(
            &key,
            &verifier,
            &InferencePayload {
                prompt: b"x".to_vec(),
                reply_to: owner_pub,
            },
        )
        .expect("sealed");

        // The worker cannot open a request sealed to a different channel.
        assert!(worker
            .handle(&sealed_req)
            .expect("no model error")
            .is_none());
    }
}
