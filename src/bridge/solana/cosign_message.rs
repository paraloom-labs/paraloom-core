//! Deterministic settlement-transaction assembly for the co-signing round
//! (#260).
//!
//! The on-chain program requires a quorum of validators to co-sign a settlement
//! transaction. For their ed25519 signatures to interoperate, every co-signer
//! must sign the *exact same bytes* — so rather than the leader shipping an
//! opaque serialized transaction that each validator would have to parse and
//! trust, it ships a [`CoSignPayload`] of structured parameters. Each validator
//! checks those parameters against the settlement it voted to approve and then
//! rebuilds the transaction message itself with [`build_settlement_message`].
//!
//! Because the instruction builders are deterministic and the payload pins
//! every input that affects the bytes — program id, payer, blockhash, the
//! ordered co-signer set, and the settlement parameters — every honest party
//! produces a byte-identical [`Message`]. The leader signs and submits the same
//! message it collected signatures over. No transaction-message parser is
//! involved, so a malicious leader cannot smuggle a different recipient or
//! amount past a validator: the validator only ever signs a message it built
//! from parameters it verified.

use super::instructions::{
    create_shielded_transfer_instruction, create_transact_instruction,
    create_update_merkle_root_instruction, create_withdraw_instruction,
};
use crate::bridge::{BridgeError, Result};
use serde::{Deserialize, Serialize};
use solana_sdk::{hash::Hash, message::Message, pubkey::Pubkey};

/// The settlement-specific parameters of a co-sign payload — the fields the
/// validator matches against the request it approved before signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SettlementParams {
    /// A `withdraw` settlement.
    Withdrawal {
        recipient: [u8; 32],
        amount: u64,
        nullifier: [u8; 32],
        expiration_slot: u64,
        /// 256-byte alt_bn128 wire proof.
        proof: Vec<u8>,
    },
    /// A `shielded_transfer` settlement.
    Transfer {
        nullifiers: [[u8; 32]; 2],
        output_commitments: [[u8; 32]; 2],
        new_merkle_root: [u8; 32],
        /// 256-byte alt_bn128 wire proof.
        proof: Vec<u8>,
    },
    /// An `update_merkle_root` settlement (#260): publish the live shielded-pool
    /// root on-chain so a subsequent `withdraw` verifies against the same root
    /// the prover used. Quorum-gated on-chain exactly like the others, so it is
    /// co-signed by the validator set rather than the authority alone.
    UpdateMerkleRoot { new_merkle_root: [u8; 32] },
    /// A v3 `transact` settlement (#350): unified 2-in/2-out spend against the
    /// program's on-chain incremental tree. `root` must be in the on-chain root
    /// history; `ext_amount < 0` withdraws `|ext_amount|` to `recipient`,
    /// `== 0` is a pure shielded transfer. Appended last so the bincode
    /// variant indices of the existing settlements stay wire-stable across a
    /// rolling upgrade.
    Transact {
        recipient: [u8; 32],
        nullifiers: [[u8; 32]; 2],
        output_commitments: [[u8; 32]; 2],
        root: [u8; 32],
        ext_amount: i64,
        /// 256-byte alt_bn128 wire proof.
        proof: Vec<u8>,
    },
}

/// Everything needed to rebuild the settlement transaction message a co-signer
/// signs (#260). Carried in `CoSignRequest.message`. Pubkeys and the blockhash
/// are raw `[u8; 32]` so the payload serializes identically on every node
/// regardless of solana-sdk serde details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoSignPayload {
    /// The paraloom program id.
    pub program_id: [u8; 32],
    /// The settling authority — also the transaction fee payer and the leader
    /// that assembles the signatures.
    pub authority: [u8; 32],
    /// The bridge vault PDA. Used only for withdrawals; ignored for transfers.
    pub bridge_vault: [u8; 32],
    /// The recent blockhash the transaction is built against. Pinning it here
    /// is what makes every co-signer's message byte-identical.
    pub blockhash: [u8; 32],
    /// The ordered co-signer wallet set, appended to the instruction as the
    /// on-chain quorum `(wallet, pda)` pairs. Order is significant: it must be
    /// identical for every co-signer or the rebuilt messages diverge.
    pub quorum_validators: Vec<[u8; 32]>,
    /// The settlement-specific parameters.
    pub params: SettlementParams,
}

impl CoSignPayload {
    /// Serialize for transport in `CoSignRequest.message`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| BridgeError::Serialization(e.to_string()))
    }

    /// Deserialize a payload received in a `CoSignRequest`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| BridgeError::Serialization(e.to_string()))
    }
}

/// Upper bound on co-signers in a single settlement transaction.
///
/// Each quorum validator contributes two accounts to the instruction
/// (`append_quorum_accounts`: the signing wallet and its registry PDA). A Solana
/// transaction message indexes its accounts with a `u8`, so more than 255
/// distinct accounts makes `Message::new_with_blockhash` panic while compiling.
/// A co-sign request arrives over the network with an attacker-controllable
/// `quorum_validators`, so an oversized set must be rejected as a typed error
/// rather than crashing the node. The cap leaves ample headroom under the 255
/// account limit (and well under the ~1232-byte transaction-size limit, which
/// binds far sooner) while never constraining a realistic BFT quorum.
pub const MAX_QUORUM_COSIGNERS: usize = 100;

/// Rebuild the exact settlement transaction [`Message`] every co-signer signs.
///
/// Deterministic in `payload`: the same payload always yields byte-identical
/// `Message::serialize()` output, which is the property the multi-signature
/// assembly relies on.
pub fn build_settlement_message(payload: &CoSignPayload) -> Result<Message> {
    // Reject an oversized co-signer set before building the message: the count
    // comes off the wire and more accounts than a transaction can index would
    // panic the message compiler (see MAX_QUORUM_COSIGNERS).
    if payload.quorum_validators.len() > MAX_QUORUM_COSIGNERS {
        return Err(BridgeError::InvalidTransaction(format!(
            "co-sign quorum has {} validators, exceeds the {} maximum",
            payload.quorum_validators.len(),
            MAX_QUORUM_COSIGNERS
        )));
    }

    let program_id = Pubkey::new_from_array(payload.program_id);
    let authority = Pubkey::new_from_array(payload.authority);
    let quorum: Vec<Pubkey> = payload
        .quorum_validators
        .iter()
        .copied()
        .map(Pubkey::new_from_array)
        .collect();

    let instruction = match &payload.params {
        SettlementParams::Withdrawal {
            recipient,
            amount,
            nullifier,
            expiration_slot,
            proof,
        } => {
            let vault = Pubkey::new_from_array(payload.bridge_vault);
            create_withdraw_instruction(
                &program_id,
                &authority,
                &vault,
                *recipient,
                *nullifier,
                *amount,
                *expiration_slot,
                proof.clone(),
                &quorum,
            )?
        }
        SettlementParams::Transfer {
            nullifiers,
            output_commitments,
            new_merkle_root,
            proof,
        } => create_shielded_transfer_instruction(
            &program_id,
            &authority,
            *nullifiers,
            *output_commitments,
            *new_merkle_root,
            proof.clone(),
            &quorum,
        )?,
        SettlementParams::UpdateMerkleRoot { new_merkle_root } => {
            create_update_merkle_root_instruction(
                &program_id,
                &authority,
                *new_merkle_root,
                &quorum,
            )?
        }
        SettlementParams::Transact {
            recipient,
            nullifiers,
            output_commitments,
            root,
            ext_amount,
            proof,
        } => {
            let vault = Pubkey::new_from_array(payload.bridge_vault);
            create_transact_instruction(
                &program_id,
                &authority,
                &vault,
                *recipient,
                *nullifiers,
                *output_commitments,
                *root,
                *ext_amount,
                proof.clone(),
                &quorum,
            )?
        }
    };

    let blockhash = Hash::new_from_array(payload.blockhash);
    Ok(Message::new_with_blockhash(
        &[instruction],
        Some(&authority),
        &blockhash,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_withdrawal_payload() -> CoSignPayload {
        CoSignPayload {
            program_id: [1u8; 32],
            authority: [2u8; 32],
            bridge_vault: [3u8; 32],
            blockhash: [4u8; 32],
            quorum_validators: vec![[2u8; 32], [5u8; 32]],
            params: SettlementParams::Withdrawal {
                recipient: [6u8; 32],
                amount: 1_000_000_000,
                nullifier: [7u8; 32],
                expiration_slot: u64::MAX,
                proof: vec![0u8; 256],
            },
        }
    }

    fn sample_transfer_payload() -> CoSignPayload {
        CoSignPayload {
            program_id: [1u8; 32],
            authority: [2u8; 32],
            bridge_vault: [0u8; 32],
            blockhash: [4u8; 32],
            quorum_validators: vec![[2u8; 32], [5u8; 32]],
            params: SettlementParams::Transfer {
                nullifiers: [[8u8; 32], [9u8; 32]],
                output_commitments: [[10u8; 32], [11u8; 32]],
                new_merkle_root: [12u8; 32],
                proof: vec![0u8; 256],
            },
        }
    }

    fn sample_transact_payload() -> CoSignPayload {
        CoSignPayload {
            program_id: [1u8; 32],
            authority: [2u8; 32],
            bridge_vault: [3u8; 32],
            blockhash: [4u8; 32],
            quorum_validators: vec![[2u8; 32], [5u8; 32]],
            params: SettlementParams::Transact {
                recipient: [6u8; 32],
                nullifiers: [[8u8; 32], [9u8; 32]],
                output_commitments: [[10u8; 32], [11u8; 32]],
                root: [12u8; 32],
                ext_amount: -500,
                proof: vec![0u8; 256],
            },
        }
    }

    #[test]
    fn payload_round_trips_through_bytes() {
        for payload in [
            sample_withdrawal_payload(),
            sample_transfer_payload(),
            sample_transact_payload(),
        ] {
            let bytes = payload.to_bytes().expect("serialize");
            let decoded = CoSignPayload::from_bytes(&bytes).expect("deserialize");
            assert_eq!(decoded, payload);
        }
    }

    /// The `Transact` variant was appended after the settlements already on the
    /// wire; bincode encodes an enum as its variant index, so the pre-existing
    /// variants' indices must never shift — a node running the previous release
    /// must still decode a `Withdrawal` payload from a node running this one
    /// during a rolling upgrade. Pins the first four bytes (the little-endian
    /// u32 variant index) of each variant's encoding.
    #[test]
    fn settlement_variant_indices_are_wire_stable() {
        let cases: [(CoSignPayload, u32); 3] = [
            (sample_withdrawal_payload(), 0),
            (sample_transfer_payload(), 1),
            (sample_transact_payload(), 3),
        ];
        for (payload, index) in cases {
            let bytes = bincode::serialize(&payload.params).expect("serialize params");
            assert_eq!(
                &bytes[..4],
                &index.to_le_bytes(),
                "variant index drifted — this breaks rolling-upgrade decoding"
            );
        }
    }

    #[test]
    fn message_build_is_deterministic_for_transact() {
        let payload = sample_transact_payload();
        let a = build_settlement_message(&payload).expect("build a");
        let b = build_settlement_message(&payload).expect("build b");
        assert_eq!(a.serialize(), b.serialize());
    }

    #[test]
    fn different_transact_recipient_changes_the_message() {
        // Same security property as withdraw: a validator that rebuilds from
        // verified parameters never signs a substituted transact recipient.
        let mut tampered = sample_transact_payload();
        if let SettlementParams::Transact {
            ref mut recipient, ..
        } = tampered.params
        {
            *recipient = [99u8; 32];
        }
        let original = build_settlement_message(&sample_transact_payload()).expect("build");
        let changed = build_settlement_message(&tampered).expect("build tampered");
        assert_ne!(original.serialize(), changed.serialize());
    }

    #[test]
    fn message_build_is_deterministic_for_withdrawal() {
        let payload = sample_withdrawal_payload();
        let a = build_settlement_message(&payload).expect("build a");
        let b = build_settlement_message(&payload).expect("build b");
        assert_eq!(
            a.serialize(),
            b.serialize(),
            "the same payload must yield byte-identical message bytes for the signatures to interoperate"
        );
    }

    #[test]
    fn message_build_is_deterministic_for_transfer() {
        let payload = sample_transfer_payload();
        let a = build_settlement_message(&payload).expect("build a");
        let b = build_settlement_message(&payload).expect("build b");
        assert_eq!(a.serialize(), b.serialize());
    }

    #[test]
    fn rebuilding_from_transported_bytes_matches_the_original() {
        // A validator receives the payload bytes, rebuilds, and must land on the
        // exact message the leader will submit.
        let payload = sample_withdrawal_payload();
        let leader_message = build_settlement_message(&payload).expect("leader build");

        let bytes = payload.to_bytes().expect("serialize");
        let received = CoSignPayload::from_bytes(&bytes).expect("deserialize");
        let validator_message = build_settlement_message(&received).expect("validator build");

        assert_eq!(
            leader_message.serialize(),
            validator_message.serialize(),
            "a validator rebuilding from the transported payload must match the leader's message"
        );
    }

    #[test]
    fn oversized_quorum_is_rejected_not_panicked() {
        // The co-signer set arrives off the wire. An attacker-sized quorum that
        // would overflow the transaction's u8 account index must return a typed
        // error rather than panic the message compiler (remote node crash).
        let mut payload = sample_withdrawal_payload();
        payload.quorum_validators = vec![[7u8; 32]; MAX_QUORUM_COSIGNERS + 1];
        let err =
            build_settlement_message(&payload).expect_err("an oversized quorum must be rejected");
        assert!(matches!(err, BridgeError::InvalidTransaction(_)));

        // A quorum exactly at the cap still builds (the bound is inclusive).
        payload.quorum_validators = vec![[7u8; 32]; MAX_QUORUM_COSIGNERS];
        build_settlement_message(&payload).expect("a quorum at the cap still builds");
    }

    #[test]
    fn different_recipient_changes_the_message() {
        // The security property: a different settlement parameter yields a
        // different message, so a validator that rebuilds from verified
        // parameters never signs the leader's substituted recipient.
        let mut tampered = sample_withdrawal_payload();
        if let SettlementParams::Withdrawal {
            ref mut recipient, ..
        } = tampered.params
        {
            *recipient = [0xFF; 32];
        }
        let original = build_settlement_message(&sample_withdrawal_payload()).expect("orig");
        let other = build_settlement_message(&tampered).expect("tampered");
        assert_ne!(original.serialize(), other.serialize());
    }
}
