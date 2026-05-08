//! Fuzz target for #71. `MerklePath::verify` walks an
//! attacker-controlled authentication path of arbitrary depth and
//! shape; a malformed path must surface as `false`, never as a
//! panic. This target slices the raw fuzz input into `(leaf, root,
//! [(sibling, side), ...])` and feeds the constructed path into
//! `verify`. The path depth is capped at 64 (well above any tree
//! the production code instantiates) so a pathological input cannot
//! turn the fuzz process into an OOM probe.
//!
//! Run with: `cargo +nightly fuzz run merkle_path_verify`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paraloom::privacy::MerklePath;

const MAX_DEPTH: usize = 64;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&data[0..32]);
    let mut root = [0u8; 32];
    root.copy_from_slice(&data[32..64]);

    let mut path = Vec::new();
    let mut indices = Vec::new();
    let mut rest = &data[64..];
    while rest.len() >= 33 && path.len() < MAX_DEPTH {
        let mut sib = [0u8; 32];
        sib.copy_from_slice(&rest[0..32]);
        path.push(sib);
        indices.push(rest[32] & 1 == 1);
        rest = &rest[33..];
    }

    let mp = MerklePath { path, indices };
    let _ = mp.verify(&leaf, &root);
});
