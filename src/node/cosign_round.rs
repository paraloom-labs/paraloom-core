//! Leader-side co-signing round orchestration (#260).
//!
//! When this node reaches a withdrawal/transfer quorum it is the settling node —
//! the round leader. [`run_cosign_round`] turns an approved settlement into a
//! fully co-signed transaction: it builds the canonical [`CoSignPayload`], signs
//! the rebuilt message itself, asks each other approving validator to co-sign
//! the same message over the co-sign protocol, and assembles the collected
//! signatures into one transaction that satisfies the on-chain validator quorum.
//!
//! The network send is injected so the orchestration is unit-testable without a
//! swarm; the live caller wires it to `NetworkManager::send_cosign_request`.

use crate::bridge::solana::{
    assemble_transaction, build_settlement_message, signature_is_valid, CoSignPayload,
    SettlementParams,
};
use crate::bridge::{BridgeError, Result};
use crate::network::{CoSignRequest, CoSignResponse, SettlementKind};
use crate::types::NodeId;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::collections::HashMap;
use std::future::Future;

/// Run the leader-side co-signing round and return the assembled, fully-signed
/// settlement transaction (#260).
///
/// - `leader` is this node's settlement keypair; it is the fee payer and one of
///   the quorum co-signers.
/// - `quorum_wallets` is the initial co-signer set bound into the payload.
/// - `peers` are the other approving validators to request signatures from,
///   paired with the libp2p node to send to.
/// - `threshold` is how many distinct, verified signatures must be collected
///   (the on-chain quorum size).
/// - `send` performs one co-sign request, yielding the peer's response or
///   `None` on decline/timeout.
///
/// If a subset of peers declines or times out but the remaining responsive peers
/// plus the leader still meet or exceed `threshold`, the quorum is shrunk to the
/// responsive set and re-signed so the on-chain transaction only expects signers
/// that actually participate.
///
/// Errors if the message cannot be built, the threshold is not reached, or the
/// assembled transaction fails to verify.
#[allow(clippy::too_many_arguments)]
pub async fn run_cosign_round<S, Fut>(
    leader: &Keypair,
    program_id: Pubkey,
    bridge_vault: Pubkey,
    blockhash: [u8; 32],
    request_id: &str,
    kind: SettlementKind,
    params: SettlementParams,
    _quorum_wallets: Vec<Pubkey>,
    peers: &[(Pubkey, NodeId)],
    threshold: usize,
    send: S,
) -> Result<Transaction>
where
    S: Fn(NodeId, CoSignRequest) -> Fut,
    Fut: Future<Output = Option<CoSignResponse>>,
{
    let mut current_peers: Vec<(Pubkey, NodeId)> = peers.to_vec();

    loop {
        if 1 + current_peers.len() < threshold {
            return Err(BridgeError::Serialization(format!(
                "co-sign quorum not reached: {} available signers, {threshold} required",
                1 + current_peers.len()
            )));
        }

        let mut current_quorum_wallets = vec![leader.pubkey()];
        current_quorum_wallets.extend(current_peers.iter().map(|(w, _)| *w));

        let payload = CoSignPayload {
            program_id: program_id.to_bytes(),
            authority: leader.pubkey().to_bytes(),
            bridge_vault: bridge_vault.to_bytes(),
            blockhash,
            quorum_validators: current_quorum_wallets
                .iter()
                .map(|p| p.to_bytes())
                .collect(),
            params: params.clone(),
        };

        let message = build_settlement_message(&payload)?;
        let own_sig = leader.sign_message(&message.serialize()).as_ref().to_vec();

        let request = CoSignRequest {
            request_id: request_id.to_string(),
            kind,
            message: payload.to_bytes()?,
        };

        let message_bytes = message.serialize();
        let mut responsive_peers = Vec::new();
        let mut signatures: HashMap<Pubkey, Vec<u8>> = HashMap::new();
        signatures.insert(leader.pubkey(), own_sig);

        for (wallet, node_id) in &current_peers {
            let Some(response) = send(node_id.clone(), request.clone()).await else {
                continue; // declined or timed out
            };
            let (Some(sig), Ok(resp_wallet)) =
                (response.signature, response.wallet_pubkey.parse::<Pubkey>())
            else {
                continue;
            };
            if resp_wallet != *wallet {
                continue;
            }
            if !signature_is_valid(wallet, &sig, &message_bytes) {
                log::warn!("co-sign signature from {wallet} did not verify; ignoring");
                continue;
            }
            responsive_peers.push((*wallet, node_id.clone()));
            signatures.insert(*wallet, sig);
        }

        if responsive_peers.len() == current_peers.len() {
            // All peers in current set signed successfully!
            return assemble_transaction(message, &signatures);
        }

        // Some peer(s) declined or timed out.
        // Check if responsive peers + leader still meet the threshold.
        if 1 + responsive_peers.len() < threshold {
            return Err(BridgeError::Serialization(format!(
                "co-sign quorum not reached: {} signatures gathered, {threshold} required",
                1 + responsive_peers.len()
            )));
        }

        // Shrunk peer set still satisfies quorum. Shrink and retry round so that
        // the Solana transaction only bakes in the signers who actually sign!
        current_peers = responsive_peers;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transact_params() -> SettlementParams {
        SettlementParams::Transact {
            recipient: [6u8; 32],
            nullifiers: [[7u8; 32], [8u8; 32]],
            output_commitments: [[9u8; 32], [10u8; 32]],
            root: [11u8; 32],
            ext_amount: -1_000_000_000,
            proof: vec![0u8; 256],
        }
    }

    // A co-signer that signs whatever payload it is sent, as an honest validator
    // would after verifying — used to drive the round in tests.
    fn honest_response(kp: &Keypair, request: &CoSignRequest) -> CoSignResponse {
        let payload = CoSignPayload::from_bytes(&request.message).expect("payload");
        let message = build_settlement_message(&payload).expect("message");
        let sig = kp.sign_message(&message.serialize());
        CoSignResponse {
            request_id: request.request_id.clone(),
            wallet_pubkey: kp.pubkey().to_string(),
            signature: Some(sig.as_ref().to_vec()),
        }
    }

    #[tokio::test]
    async fn assembles_a_fully_co_signed_transaction() {
        let leader = Keypair::new();
        let p1 = Keypair::new();
        let p2 = Keypair::new();

        let quorum_wallets = vec![leader.pubkey(), p1.pubkey(), p2.pubkey()];
        let peers = vec![
            (p1.pubkey(), NodeId(vec![1])),
            (p2.pubkey(), NodeId(vec![2])),
        ];

        let tx = run_cosign_round(
            &leader,
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([3u8; 32]),
            [4u8; 32],
            "req-1",
            SettlementKind::Transact,
            transact_params(),
            quorum_wallets,
            &peers,
            3,
            |peer, request| {
                let (p1, p2) = (&p1, &p2);
                async move {
                    let kp = if peer == NodeId(vec![1]) { p1 } else { p2 };
                    Some(honest_response(kp, &request))
                }
            },
        )
        .await
        .expect("round completes");

        assert!(
            tx.verify().is_ok(),
            "the assembled co-signed transaction must verify"
        );
        assert_eq!(
            tx.signatures.len(),
            3,
            "leader plus both co-signers must have signed"
        );
    }

    #[tokio::test]
    async fn errors_when_a_co_signer_declines_below_threshold() {
        let leader = Keypair::new();
        let p1 = Keypair::new();

        let quorum_wallets = vec![leader.pubkey(), p1.pubkey()];
        let peers = vec![(p1.pubkey(), NodeId(vec![1]))];

        // The only peer declines, so the threshold of 2 cannot be reached.
        let result = run_cosign_round(
            &leader,
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([3u8; 32]),
            [4u8; 32],
            "req-1",
            SettlementKind::Transact,
            transact_params(),
            quorum_wallets,
            &peers,
            2,
            |_peer, _request| async move { None },
        )
        .await;

        assert!(result.is_err(), "an unmet quorum must error, not submit");
    }

    #[tokio::test]
    async fn assembles_transaction_when_one_peer_declines_but_threshold_met() {
        let leader = Keypair::new();
        let p1 = Keypair::new();
        let p2 = Keypair::new();

        let quorum_wallets = vec![leader.pubkey(), p1.pubkey(), p2.pubkey()];
        let peers = vec![
            (p1.pubkey(), NodeId(vec![1])),
            (p2.pubkey(), NodeId(vec![2])),
        ];

        // p1 responds honestly; p2 declines (returns None).
        // Threshold is 2 (leader + 1 peer), so it should shrink to [leader, p1] and succeed!
        let tx = run_cosign_round(
            &leader,
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([3u8; 32]),
            [4u8; 32],
            "req-1",
            SettlementKind::Transact,
            transact_params(),
            quorum_wallets,
            &peers,
            2,
            |peer, request| {
                let p1 = &p1;
                async move {
                    if peer == NodeId(vec![1]) {
                        Some(honest_response(p1, &request))
                    } else {
                        None
                    }
                }
            },
        )
        .await
        .expect("round completes with shrunk quorum");

        assert!(
            tx.verify().is_ok(),
            "the assembled co-signed transaction must verify"
        );
        assert_eq!(
            tx.signatures.len(),
            2,
            "leader plus the one responding co-signer must have signed"
        );
        assert_eq!(tx.message.account_keys[0], leader.pubkey());
        assert_eq!(tx.message.account_keys[1], p1.pubkey());
    }
}
