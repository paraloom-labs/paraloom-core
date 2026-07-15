//! Wire-format parity pins for the v3 instructions (#350).
//!
//! The off-chain builders in `src/bridge/solana/instructions.rs` hardcode
//! Anchor's instruction discriminators and rely on borsh field order matching
//! the on-chain signatures. The workspace crate and this program crate cannot
//! depend on each other, so these tests pin Anchor's *actually generated*
//! encoding to the exact byte layout the off-chain side hardcodes — if either
//! side drifts (renamed instruction, reordered field, changed width), a pin
//! here fails at unit time instead of as an opaque on-chain decode error.

use anchor_lang::InstructionData;
use paraloom_program::instruction;

/// `sha256("global:transact")[..8]` — must match
/// `discriminators::TRANSACT` in the off-chain builder.
const TRANSACT_DISC: [u8; 8] = [217, 149, 130, 143, 221, 52, 252, 119];
/// `sha256("global:deposit_note")[..8]` — must match
/// `discriminators::DEPOSIT_NOTE`.
const DEPOSIT_NOTE_DISC: [u8; 8] = [75, 212, 96, 185, 178, 167, 29, 57];
/// `sha256("global:initialize_merkle_tree")[..8]` — must match
/// `discriminators::INITIALIZE_MERKLE_TREE`.
const INITIALIZE_MERKLE_TREE_DISC: [u8; 8] = [67, 143, 80, 157, 177, 227, 11, 238];

#[test]
fn transact_wire_layout_matches_offchain_builder() {
    let data = instruction::Transact {
        nullifiers: [[0xAB; 32], [0xCD; 32]],
        output_commitments: [[0x11; 32], [0x22; 32]],
        root: [0x33; 32],
        ext_amount: -2,
        proof: vec![0xEF; 3],
        expiration_slot: 0,
    }
    .data();

    assert_eq!(&data[..8], &TRANSACT_DISC);
    // [nullifiers (64) | output_commitments (64) | root (32) |
    //  ext_amount (8, i64 LE) | proof_len (4) | proof…]
    assert_eq!(&data[8..40], &[0xAB; 32]);
    assert_eq!(&data[40..72], &[0xCD; 32]);
    assert_eq!(&data[72..104], &[0x11; 32]);
    assert_eq!(&data[104..136], &[0x22; 32]);
    assert_eq!(&data[136..168], &[0x33; 32]);
    // ext_amount = -2 in little-endian two's complement — a withdrawal's
    // negative sign survives the wire.
    assert_eq!(
        &data[168..176],
        &[0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    );
    assert_eq!(&data[176..180], &[3, 0, 0, 0]);
    assert_eq!(&data[180..], &[0xEF; 3]);
}

#[test]
fn deposit_note_wire_layout_matches_offchain_builder() {
    let data = instruction::DepositNote {
        amount: 1_000_000,
        pubkey: [7u8; 32],
        blinding: [8u8; 32],
    }
    .data();

    assert_eq!(&data[..8], &DEPOSIT_NOTE_DISC);
    // [amount (8, u64 LE) | pubkey (32) | blinding (32)]
    assert_eq!(&data[8..16], &1_000_000u64.to_le_bytes());
    assert_eq!(&data[16..48], &[7u8; 32]);
    assert_eq!(&data[48..80], &[8u8; 32]);
    assert_eq!(data.len(), 80);
}

#[test]
fn initialize_merkle_tree_wire_layout_matches_offchain_builder() {
    let data = instruction::InitializeMerkleTree {}.data();
    assert_eq!(data, INITIALIZE_MERKLE_TREE_DISC.to_vec());
}
