//! Encrypted note delivery (#196).
//!
//! A shielded transfer's output note must reach its recipient so they can
//! discover and spend it. Paraloom's spend model is capability-based — knowing
//! a note's `{amount, randomness, recipient}` is the authority to spend it — so
//! delivery means encrypting those fields to the recipient.
//!
//! The scheme is NaCl `crypto_box` (X25519 + XSalsa20-Poly1305) with a fresh
//! ephemeral sender key per output (unlinkable, Sapling-style). The
//! `crypto_box` crate is byte-compatible with the wallet's `tweetnacl.box` —
//! same X25519/HSalsa20 key agreement and the same `tag(16) || ciphertext`
//! layout — so ciphertexts cross between them unchanged. The `tweetnacl`
//! interop vector in the tests pins this.

use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SalsaBox, SecretKey,
};

/// The spend capability delivered to a recipient. Encoded as
/// `amount(8, LE) || randomness(32) || recipient(32)` = 72 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotePlaintext {
    pub amount: u64,
    pub randomness: [u8; 32],
    pub recipient: [u8; 32],
}

impl NotePlaintext {
    /// 72-byte canonical encoding (must match the wallet's `noteCrypto`).
    pub fn to_bytes(&self) -> [u8; 72] {
        let mut out = [0u8; 72];
        out[..8].copy_from_slice(&self.amount.to_le_bytes());
        out[8..40].copy_from_slice(&self.randomness);
        out[40..].copy_from_slice(&self.recipient);
        out
    }

    /// Parse the 72-byte encoding; `None` on a wrong length.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 72 {
            return None;
        }
        let mut amount = [0u8; 8];
        amount.copy_from_slice(&b[..8]);
        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(&b[8..40]);
        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(&b[40..]);
        Some(Self {
            amount: u64::from_le_bytes(amount),
            randomness,
            recipient,
        })
    }
}

/// An encrypted note: ephemeral X25519 public key, 24-byte nonce, and the NaCl
/// ciphertext (`tag(16) || ct`). Delivered opaquely through the transfer flow.
///
/// Deliberately **not** `Serialize`/`Deserialize`. The canonical encoding is
/// [`EncryptedNote::to_bytes`] / [`EncryptedNote::from_bytes`], and a derived
/// serde impl would be a second wire representation of the same envelope —
/// exactly the drift this codec exists to remove. A boundary that needs to
/// carry one in JSON carries the canonical bytes as a hex string.
///
/// `ct` always carries at least its 16-byte Poly1305 tag, because `crypto_box`
/// emits one even for an empty plaintext. Every constructor in this crate
/// upholds that ([`seal`] and [`EncryptedNote::from_bytes`]), but the fields
/// are public, so a hand-built value can violate it — and `to_bytes` would
/// then emit bytes that `from_bytes` rejects. See the PR discussion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedNote {
    pub epk: [u8; 32],
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

/// Permanently reserved envelope tag. Never allocated to a version, so that an
/// all-zero or truncated buffer cannot read as a valid envelope.
pub const ENVELOPE_TAG_RESERVED: u8 = 0;

/// v1: `crypto_box` (X25519 + XSalsa20-Poly1305). The remainder is
/// `epk(32) || nonce(24) || ct`, byte-identical to the pre-tag encoding.
pub const ENVELOPE_TAG_V1: u8 = 1;

/// Smallest well-formed v1 remainder: `epk(32) || nonce(24)`, plus the 16-byte
/// Poly1305 tag that every `crypto_box` output carries even when the sealed
/// plaintext is empty (see the `ct` field: `tag(16) || ct`).
const V1_MIN_REMAINDER: usize = 32 + 24 + 16;

/// Why an envelope could not be parsed.
///
/// The distinction between [`EnvelopeError::UnknownVersion`] and the other
/// variants is load-bearing rather than cosmetic: a component that only
/// *relays* envelopes has to tell "I cannot parse this" apart from "this is
/// not a valid envelope". See [`check_relayable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// No bytes at all, so not even a tag.
    Empty,
    /// The reserved `0` tag: invalid in every version, now and in future.
    ReservedTag,
    /// A tag this build does not implement. Carries no claim about whether the
    /// remainder is well-formed — this build has no way to judge that.
    UnknownVersion(u8),
    /// A recognised tag whose remainder does not match that version's layout.
    Malformed(u8),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty envelope (no version tag)"),
            Self::ReservedTag => write!(f, "reserved envelope tag 0"),
            Self::UnknownVersion(v) => write!(f, "unimplemented envelope version {v}"),
            Self::Malformed(v) => write!(f, "malformed v{v} envelope"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl EncryptedNote {
    /// Canonical wire encoding: `tag(1) || <version-defined remainder>`.
    ///
    /// The tag selects a *parser* rather than sitting inside a fixed layout:
    /// the bytes after it are defined entirely by the version, with no
    /// structure shared across versions beyond the tag. A later hybrid or
    /// post-quantum suite has an encapsulation far larger than 32 bytes
    /// (X-Wing's is 1120), so a fixed `epk` slot at offset 1 would be the same
    /// wall one byte further in.
    ///
    /// The tag covers the *envelope* — key agreement, symmetric construction,
    /// framing — and not the schema of whatever is sealed inside: [`seal`]
    /// takes an arbitrary `&[u8]`, so the envelope is the only domain the note
    /// path and the compute path actually share. Versioning `NotePlaintext`
    /// needs its own discriminator, on the transact path only.
    ///
    /// The in-memory struct is the v1 shape, so this always writes
    /// [`ENVELOPE_TAG_V1`]. Every boundary that puts an envelope on a wire
    /// goes through this and [`EncryptedNote::from_bytes`], so no two of them
    /// can drift apart independently.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 24 + self.ct.len());
        out.push(ENVELOPE_TAG_V1);
        out.extend_from_slice(&self.epk);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct);
        out
    }

    /// Parse a canonical encoding.
    ///
    /// An unrecognised tag is rejected rather than fallen back on: a reader
    /// that cannot parse a version must not try the one it knows. That is also
    /// what makes the tag safe outside the AEAD — `crypto_box` has no AAD, so
    /// the tag is unauthenticated, and with no fallback the only thing
    /// flipping it achieves is a rejection the recipient would have reached
    /// anyway.
    pub fn from_bytes(b: &[u8]) -> Result<Self, EnvelopeError> {
        let (&tag, rest) = b.split_first().ok_or(EnvelopeError::Empty)?;
        match tag {
            ENVELOPE_TAG_RESERVED => Err(EnvelopeError::ReservedTag),
            ENVELOPE_TAG_V1 => {
                if rest.len() < V1_MIN_REMAINDER {
                    return Err(EnvelopeError::Malformed(ENVELOPE_TAG_V1));
                }
                let mut epk = [0u8; 32];
                epk.copy_from_slice(&rest[..32]);
                let mut nonce = [0u8; 24];
                nonce.copy_from_slice(&rest[32..56]);
                Ok(Self {
                    epk,
                    nonce,
                    ct: rest[56..].to_vec(),
                })
            }
            other => Err(EnvelopeError::UnknownVersion(other)),
        }
    }
}

/// Whether a relay may forward this blob.
///
/// The settlement path does not open envelopes: `canonical_id` excludes the
/// ciphertexts and nothing downstream in core depends on their content, so a
/// validator here is a *carrier*, not a consumer. It therefore rejects only
/// what is invalid under every version — an empty blob and the reserved tag —
/// plus a v1 blob that fails the v1 parser, and relays every other tag
/// untouched.
///
/// **The catch-all arm is deliberate and must stay a catch-all.** Making this
/// fail closed on a compiled-in set of known versions would put a core release
/// on the upgrade critical path for every future format: a wallet could not
/// submit a v2 note through existing nodes until every relay had shipped v2
/// support, even though core still would not care what is inside. It would
/// also make acceptance depend on which relay a note lands on during a rollout,
/// which is a worse failure mode than a consistent accept or reject. This is
/// the opposite of the exhaustive `match` at the settlement seam (#679), and
/// for the opposite reason: there core is the consumer, here it is the carrier.
///
/// Note also that an old build cannot do better than this on an unknown tag.
/// Any structural check it could apply would be a v1 check under a general
/// name: a minimum length would forbid a legitimately shorter future format,
/// and a maximum would not survive a 1120-byte encapsulation.
///
/// Rejecting here is hygiene, not safety. The ciphertext is not
/// settlement-bound — nullifier PDAs, quorum and the proof gate the funds, and
/// none of them touch these bytes.
pub fn check_relayable(blob: &[u8]) -> Result<(), EnvelopeError> {
    match blob.first() {
        None => Err(EnvelopeError::Empty),
        Some(&ENVELOPE_TAG_RESERVED) => Err(EnvelopeError::ReservedTag),
        Some(&ENVELOPE_TAG_V1) => EncryptedNote::from_bytes(blob).map(|_| ()),
        Some(_) => Ok(()),
    }
}

/// Seal arbitrary `plaintext` to `recipient_pub` (an X25519 public key) under a
/// fresh ephemeral sender key, so two seals to the same recipient are
/// unlinkable. The `ct` is `tag(16) || ciphertext`, the same NaCl `box` format
/// as `encrypt_note` and `tweetnacl.box` — only openable with the recipient's
/// X25519 **secret** key. This is the correct primitive for any recipient-only
/// payload (e.g. confidential compute input/output), replacing schemes that
/// encrypt under a public address directly.
pub fn seal(recipient_pub: &[u8; 32], plaintext: &[u8]) -> EncryptedNote {
    let eph = SecretKey::generate(&mut OsRng);
    let epk = *eph.public_key().as_bytes();
    let salsa = SalsaBox::new(&PublicKey::from(*recipient_pub), &eph);

    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ct = salsa
        .encrypt(&nonce, plaintext)
        .expect("XSalsa20-Poly1305 encryption of an in-memory buffer cannot fail");
    // `.into()` avoids naming the (deprecated-in-0.14) GenericArray type.
    let nonce_bytes: [u8; 24] = nonce.into();

    EncryptedNote {
        epk,
        nonce: nonce_bytes,
        ct,
    }
}

/// Open a `seal`ed box with the recipient's X25519 `secret`, returning the raw
/// plaintext bytes. `None` on any failure (wrong key or tampered ciphertext).
pub fn open(secret: &[u8; 32], sealed: &EncryptedNote) -> Option<Vec<u8>> {
    let salsa = SalsaBox::new(&PublicKey::from(sealed.epk), &SecretKey::from(*secret));
    // `.into()` builds the nonce without naming the deprecated GenericArray type.
    salsa.decrypt(&sealed.nonce.into(), sealed.ct.as_ref()).ok()
}

/// Encrypt `note` to `recipient_pub` (an X25519 public key) under a fresh
/// ephemeral sender key — so two outputs to the same recipient are unlinkable.
/// The `ct` is `tag(16) || ciphertext`, identical to `tweetnacl.box`.
pub fn encrypt_note(recipient_pub: &[u8; 32], note: &NotePlaintext) -> EncryptedNote {
    seal(recipient_pub, note.to_bytes().as_ref())
}

/// Try to decrypt `note` with the X25519 `secret`. Returns `None` on any
/// failure (wrong key, tampered ciphertext, malformed length) — callers
/// trial-decrypt every delivered note and silently skip the ones not for them.
pub fn decrypt_note(secret: &[u8; 32], note: &EncryptedNote) -> Option<NotePlaintext> {
    NotePlaintext::from_bytes(&open(secret, note)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut o = [0u8; 32];
        o.copy_from_slice(&v);
        o
    }

    #[test]
    fn round_trip_recovers_the_note() {
        let secret = SecretKey::generate(&mut OsRng);
        let pubkey = *secret.public_key().as_bytes();
        let note = NotePlaintext {
            amount: 1_000_000,
            randomness: [0x11; 32],
            recipient: [0x22; 32],
        };
        let enc = encrypt_note(&pubkey, &note);
        let got = decrypt_note(&secret.to_bytes(), &enc).expect("decrypt");
        assert_eq!(got, note);
    }

    #[test]
    fn wrong_key_decrypts_to_none() {
        let secret = SecretKey::generate(&mut OsRng);
        let other = SecretKey::generate(&mut OsRng);
        let note = NotePlaintext {
            amount: 42,
            randomness: [1; 32],
            recipient: [2; 32],
        };
        let enc = encrypt_note(secret.public_key().as_bytes(), &note);
        assert!(decrypt_note(&other.to_bytes(), &enc).is_none());
    }

    #[test]
    fn seal_open_round_trips_arbitrary_bytes() {
        // Unlike the fixed 72-byte note, `seal` takes any payload (e.g. a
        // confidential compute input/output blob) and can only be opened with
        // the recipient's SECRET key — the fix for encrypting under a public
        // address directly (#562).
        let secret = SecretKey::generate(&mut OsRng);
        let pubkey = *secret.public_key().as_bytes();
        let payload = b"confidential compute payload \x00\x01\x02 of arbitrary length".to_vec();

        let sealed = seal(&pubkey, &payload);
        assert_eq!(open(&secret.to_bytes(), &sealed).expect("open"), payload);
    }

    #[test]
    fn open_rejects_wrong_secret_and_tampering() {
        let secret = SecretKey::generate(&mut OsRng);
        let other = SecretKey::generate(&mut OsRng);
        let mut sealed = seal(secret.public_key().as_bytes(), b"secret result");

        // The public key alone (or any other key) cannot open it.
        assert!(open(&other.to_bytes(), &sealed).is_none());

        // A flipped ciphertext byte fails the Poly1305 tag.
        sealed.ct[0] ^= 0xff;
        assert!(open(&secret.to_bytes(), &sealed).is_none());
    }

    /// Interop vector produced by the wallet's `tweetnacl.box` (see #196). Core
    /// must decrypt a ciphertext the wallet encrypted — this pins the X25519
    /// key agreement, the XSalsa20-Poly1305 primitive, the `tag || ct` byte
    /// order, and the 72-byte `NotePlaintext` layout against the wallet.
    #[test]
    fn decrypts_a_tweetnacl_ciphertext() {
        let recipient_secret =
            hex32("0707070707070707070707070707070707070707070707070707070707070707");
        let epk = hex32("57db4b359f23ae5e146e4e2512056704722506348c150c14753d0c933d04d421");
        let nonce_v = hex::decode("030303030303030303030303030303030303030303030303").unwrap();
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_v);
        let ct = hex::decode(
            "6e909666a8a7350561d9d30b7e3f792c3e0a7606ef914050f9221e859f6462c8bfa072155e454186d5b343647917e44a1be8753588eba7def1d12e31ea23c40673f3c4cdf446dbbc49235f0e04c90909eff8f12485fbee62",
        )
        .unwrap();
        let enc = EncryptedNote { epk, nonce, ct };

        let got = decrypt_note(&recipient_secret, &enc).expect("decrypt tweetnacl ciphertext");
        assert_eq!(got.amount, 1_000_000);
        assert_eq!(got.randomness, [0x11; 32]);
        assert_eq!(got.recipient, [0x22; 32]);
    }

    /// A v1 envelope built from known filler, so the byte layout is pinned
    /// independently of any key material. The codec is pure framing and never
    /// inspects the sealed bytes, so filler is the right input here; real
    /// crypto stays with the tweetnacl vector above.
    fn v1_fixture(ct_len: usize) -> EncryptedNote {
        let epk: [u8; 32] = std::array::from_fn(|i| 0xA0 + i as u8);
        let nonce: [u8; 24] = std::array::from_fn(|i| 0xC0 + i as u8);
        EncryptedNote {
            epk,
            nonce,
            ct: (0..ct_len).map(|i| i as u8).collect(),
        }
    }

    #[test]
    fn envelope_round_trips_and_pins_the_layout() {
        // 72-byte NotePlaintext + 16-byte tag is the transact-path shape.
        let note = v1_fixture(88);
        let bytes = note.to_bytes();

        assert_eq!(bytes.len(), 145, "1 + 32 + 24 + 88");
        assert_eq!(bytes[0], ENVELOPE_TAG_V1);
        // v1's remainder is byte-identical to the pre-tag encoding.
        assert_eq!(&bytes[1..33], &note.epk);
        assert_eq!(&bytes[33..57], &note.nonce);
        assert_eq!(&bytes[57..], &note.ct[..]);
        assert_eq!(EncryptedNote::from_bytes(&bytes).unwrap(), note);
    }

    #[test]
    fn envelope_does_not_hardcode_the_note_ciphertext_length() {
        // `seal` takes an arbitrary payload, so the compute path produces
        // envelopes on either side of the 88-byte note shape.
        for ct_len in [16, 160, 1024] {
            let note = v1_fixture(ct_len);
            assert_eq!(
                EncryptedNote::from_bytes(&note.to_bytes()).unwrap(),
                note,
                "ct_len {ct_len}"
            );
        }
    }

    #[test]
    fn codec_rejects_reserved_unknown_and_malformed() {
        let good = v1_fixture(88).to_bytes();

        let mut reserved = good.clone();
        reserved[0] = ENVELOPE_TAG_RESERVED;
        assert_eq!(
            EncryptedNote::from_bytes(&reserved),
            Err(EnvelopeError::ReservedTag)
        );

        let mut unknown = good.clone();
        unknown[0] = 2;
        assert_eq!(
            EncryptedNote::from_bytes(&unknown),
            Err(EnvelopeError::UnknownVersion(2))
        );

        assert_eq!(EncryptedNote::from_bytes(&[]), Err(EnvelopeError::Empty));
        assert_eq!(
            EncryptedNote::from_bytes(&[ENVELOPE_TAG_V1]),
            Err(EnvelopeError::Malformed(1))
        );
        // 57 bytes: well-formed epk and nonce, but an empty sealed body. A
        // `crypto_box` ciphertext always carries its 16-byte tag, so this
        // cannot be real output.
        assert_eq!(
            EncryptedNote::from_bytes(&good[..57]),
            Err(EnvelopeError::Malformed(1))
        );
    }

    /// The carrier rule. Core relays on the settlement path, so an unknown
    /// version passes ingress even though the codec cannot parse it — see
    /// `check_relayable` for why this must not become fail-closed.
    #[test]
    fn relay_forwards_unknown_versions_but_not_the_reserved_tag() {
        let good = v1_fixture(88).to_bytes();
        assert!(check_relayable(&good).is_ok());

        for tag in [2u8, 0x7f, 0xff] {
            let mut unknown = good.clone();
            unknown[0] = tag;
            assert!(
                check_relayable(&unknown).is_ok(),
                "tag {tag} must relay opaquely"
            );
        }

        // A one-byte unknown version. This is the case that forbids a shared
        // minimum length in front of the version dispatch: a future format may
        // legitimately be shorter than v1, and a carrier has no standing to
        // assume otherwise. A `blob.len() < V1_MIN_REMAINDER` guard added
        // before the match would pass every other test in this module and fail
        // only these two.
        assert!(
            check_relayable(&[2]).is_ok(),
            "an unknown version must not inherit v1's minimum length"
        );
        assert!(check_relayable(&[0xff]).is_ok());

        let mut reserved = good.clone();
        reserved[0] = ENVELOPE_TAG_RESERVED;
        assert_eq!(check_relayable(&reserved), Err(EnvelopeError::ReservedTag));
        assert_eq!(check_relayable(&[]), Err(EnvelopeError::Empty));
        // A v1 tag is held to the v1 parser even on the relay path.
        assert_eq!(
            check_relayable(&good[..57]),
            Err(EnvelopeError::Malformed(1))
        );
    }

    #[test]
    fn sealed_output_round_trips_through_the_canonical_encoding() {
        let secret = SecretKey::generate(&mut OsRng);
        let sealed = seal(secret.public_key().as_bytes(), b"payload");
        let parsed = EncryptedNote::from_bytes(&sealed.to_bytes()).expect("parse");
        assert_eq!(open(&secret.to_bytes(), &parsed).unwrap(), b"payload");
    }

    /// The checked-in interop vectors (#678), verified against this codec.
    ///
    /// The wallet and `paraloom-prover-wasm` implement the same encoding
    /// separately and are held to this file. Without reading it back here it
    /// would be an artifact that silently goes stale the first time the codec
    /// moves, which is worse than having none: the other implementations would
    /// stay pinned to bytes core no longer produces, and the version tag
    /// cannot help because both sides would still say v1.
    ///
    /// Regenerate with `cargo run --bin emit_note_envelope_vectors`.
    #[test]
    fn checked_in_interop_vectors_match_this_codec() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../vectors/note_envelope_v1.json"))
                .expect("vectors parse");

        assert_eq!(doc["tags"]["v1"].as_u64().unwrap() as u8, ENVELOPE_TAG_V1);
        assert_eq!(
            doc["tags"]["reserved"].as_u64().unwrap() as u8,
            ENVELOPE_TAG_RESERVED
        );

        let hex_of = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();

        for case in doc["encode"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let note = EncryptedNote {
                epk: hex_of(&case["epk"]).try_into().unwrap(),
                nonce: hex_of(&case["nonce"]).try_into().unwrap(),
                ct: hex_of(&case["ct"]),
            };
            let expected = hex_of(&case["bytes"]);
            assert_eq!(note.to_bytes(), expected, "encode mismatch: {name}");
            assert_eq!(
                EncryptedNote::from_bytes(&expected).expect(name),
                note,
                "decode mismatch: {name}"
            );
        }

        for case in doc["reject"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let err = EncryptedNote::from_bytes(&hex_of(&case["bytes"]))
                .expect_err(&format!("must be rejected: {name}"));
            // Compare the variant, not the payload: the vectors record which
            // rejection a reader must reach, and `UnknownVersion(2)` and
            // `UnknownVersion(9)` are the same requirement.
            assert_eq!(
                format!("{err:?}").split('(').next().unwrap(),
                case["error"].as_str().unwrap(),
                "wrong rejection for {name}"
            );
        }

        for case in doc["relay"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            assert_eq!(
                check_relayable(&hex_of(&case["bytes"])).is_ok(),
                case["relayable"].as_bool().unwrap(),
                "relay mismatch: {name}"
            );
        }
    }
}
