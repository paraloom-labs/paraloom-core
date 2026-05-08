//! Fuzz target for #71. The codec's deserialise path receives
//! attacker-controlled bytes from the network: every failure mode
//! must surface as a typed `Err`, never as a panic or an OOM. The
//! same input is run through all three deserialise entry points so
//! a single corpus exercises proof, verifying-key, and field-element
//! shapes in lockstep.
//!
//! Run with: `cargo +nightly fuzz run proof_codec_decode`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paraloom::privacy::proof_codec;

fuzz_target!(|data: &[u8]| {
    let _ = proof_codec::deserialize_proof(data);
    let _ = proof_codec::deserialize_vk(data);
    let _ = proof_codec::bytes_to_field(data);
});
