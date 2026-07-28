//! Dev tool: emit the `EncryptedNote` envelope interop vectors (#678).
//!
//! The wallet and `paraloom-prover-wasm` implement the same canonical encoding
//! in TypeScript and in wasm. Vectors are how those implementations are held to
//! this one: a reimplementation that agrees with the prose and disagrees with
//! the bytes is exactly the drift the version tag exists to surface, and prose
//! cannot catch it.
//!
//! Inputs are fixed filler rather than real key material, deliberately. The
//! codec is pure framing and never inspects the sealed bytes, so key material
//! would add nothing a reader could check while making the vectors
//! irreproducible. Real crypto is covered by the tweetnacl interop vector in
//! `note_crypto`, which pins `crypto_box` against the wallet's `tweetnacl.box`.
//!
//! Writes `vectors/note_envelope_v1.json`, which is checked in and read back by
//! `note_crypto`'s own tests, so the artifact cannot drift from the code that
//! generated it.
//!
//! `cargo run --bin emit_note_envelope_vectors`

use paraloom::privacy::note_crypto::{
    check_relayable, EncryptedNote, ENVELOPE_TAG_RESERVED, ENVELOPE_TAG_V1,
};
use std::path::Path;

const OUTPUT_PATH: &str = "vectors/note_envelope_v1.json";

/// A v1 envelope with a `ct` of `ct_len` bytes, built from position-dependent
/// filler so a reader that mixes up `epk` and `nonce` produces different bytes
/// rather than the same ones.
fn v1(ct_len: usize) -> EncryptedNote {
    EncryptedNote {
        epk: std::array::from_fn(|i| 0xA0u8.wrapping_add(i as u8)),
        nonce: std::array::from_fn(|i| 0x40u8.wrapping_add(i as u8)),
        ct: (0..ct_len).map(|i| 0x10u8.wrapping_add(i as u8)).collect(),
    }
}

fn encode_case(name: &str, note: &EncryptedNote) -> serde_json::Value {
    let bytes = note.to_bytes();
    // Round-trip here rather than trusting to_bytes alone: a vector that
    // encodes correctly but cannot be parsed back would pin the wrong thing.
    let back = EncryptedNote::from_bytes(&bytes).expect("vector must round-trip");
    assert_eq!(&back, note, "round-trip changed the envelope");
    serde_json::json!({
        "name": name,
        "epk": hex::encode(note.epk),
        "nonce": hex::encode(note.nonce),
        "ct": hex::encode(&note.ct),
        "bytes": hex::encode(&bytes),
    })
}

fn reject_case(name: &str, bytes: Vec<u8>, error: &str) -> serde_json::Value {
    let err = EncryptedNote::from_bytes(&bytes).expect_err("vector must be rejected");
    assert_eq!(
        format!("{err:?}").split('(').next().unwrap(),
        error,
        "declared error does not match the parser's"
    );
    serde_json::json!({
        "name": name,
        "bytes": hex::encode(&bytes),
        "error": error,
    })
}

fn relay_case(name: &str, bytes: Vec<u8>, relayable: bool) -> serde_json::Value {
    assert_eq!(
        check_relayable(&bytes).is_ok(),
        relayable,
        "declared relayability does not match check_relayable"
    );
    serde_json::json!({
        "name": name,
        "bytes": hex::encode(&bytes),
        "relayable": relayable,
    })
}

fn main() {
    // The smallest well-formed v1 ct: crypto_box emits a 16-byte Poly1305 tag
    // even for an empty plaintext, so nothing shorter can ever authenticate.
    let minimal = v1(16);
    // 88 bytes is the note-path shape: a 72-byte NotePlaintext plus the tag.
    let note_shaped = v1(88);
    let long = v1(1024);

    let unknown = {
        let mut b = vec![0x02];
        b.extend_from_slice(&minimal.to_bytes()[1..]);
        b
    };

    let doc = serde_json::json!({
        "description":
            "Canonical EncryptedNote envelope encoding, v1. Layout is \
             tag(1) || epk(32) || nonce(24) || ct, where ct carries its \
             16-byte Poly1305 tag. The version tag selects a parser: nothing \
             beyond the tag itself is shared across versions. An unrecognised \
             tag is never fallen back on.",
        "tags": {
            "reserved": ENVELOPE_TAG_RESERVED,
            "v1": ENVELOPE_TAG_V1,
        },
        "encode": [
            encode_case("minimal_ct", &minimal),
            encode_case("note_shaped_ct", &note_shaped),
            encode_case("long_ct", &long),
        ],
        "reject": [
            reject_case("empty", vec![], "Empty"),
            reject_case("reserved_tag_alone", vec![ENVELOPE_TAG_RESERVED], "ReservedTag"),
            reject_case(
                "reserved_tag_with_valid_remainder",
                {
                    let mut b = vec![ENVELOPE_TAG_RESERVED];
                    b.extend_from_slice(&minimal.to_bytes()[1..]);
                    b
                },
                "ReservedTag",
            ),
            reject_case("v1_tag_alone", vec![ENVELOPE_TAG_V1], "Malformed"),
            reject_case(
                "v1_one_byte_short",
                minimal.to_bytes()[..minimal.to_bytes().len() - 1].to_vec(),
                "Malformed",
            ),
            reject_case("unknown_version", unknown.clone(), "UnknownVersion"),
        ],
        "relay": [
            relay_case("v1_valid_relays", minimal.to_bytes(), true),
            relay_case("unknown_version_relays", unknown, true),
            relay_case("empty_rejected", vec![], false),
            relay_case("reserved_tag_rejected", vec![ENVELOPE_TAG_RESERVED], false),
            relay_case(
                "malformed_v1_rejected",
                vec![ENVELOPE_TAG_V1, 0x00, 0x01],
                false,
            ),
        ],
    });

    let path = std::env::var("NOTE_ENVELOPE_VECTORS").unwrap_or_else(|_| OUTPUT_PATH.to_string());
    if let Some(parent) = Path::new(&path).parent() {
        std::fs::create_dir_all(parent).expect("create vectors dir");
    }
    let mut out = serde_json::to_string_pretty(&doc).expect("serialize vectors");
    out.push('\n');
    std::fs::write(&path, out).expect("write vectors");
    println!("wrote {path}");
}
