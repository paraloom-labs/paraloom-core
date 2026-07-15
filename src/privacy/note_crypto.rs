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
use serde::{Deserialize, Serialize};

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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedNote {
    pub epk: [u8; 32],
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
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
}
