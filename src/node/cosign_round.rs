//! Leader-side co-signing round orchestration (#260, #1639).
//!
//! When this node reaches a withdrawal/transfer quorum it is the settling node —
//! the round leader. [`run_cosign_round`] turns an approved settlement into a
//! fully co-signed transaction: it builds the canonical [`CoSignPayload`], signs
//! the rebuilt message itself, asks each other approving validator to co-sign
//! the same message over the co-sign protocol, and assembles the collected
//! signatures into one transaction that satisfies the on-chain validator quorum.
//!
//! If one or more co-signers decline or time out, but the responsive subset still
//! meets `threshold`, the round retries with the reduced subset so a single
//! declining voter cannot veto an approved settlement (#1639).
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
use std::sync::Arc;

/// Run the leader-side co-signing round and return the assembled, fully-signed
/// settlement transaction (#260, #1639).
///
/// - `leader` is this node's settlement keypair; it is the fee payer and one of
///   the quorum co-signers.
/// - `quorum_wallets` is the ordered co-signer set bound into the payload (the
///   leader plus the other approving validators whose wallets are known).
/// - `peers` are the other approving validators to request signatures from,
///   paired with the libp2p node to send to.
/// - `threshold` is how many distinct, verified signatures must be collected
///   (the on-chain quorum size).
/// - `send` performs one co-sign request, yielding the peer's response or
///   `None` on decline/timeout.
///
/// If one or more co-signers decline or time out, but the responsive subset still
/// meets `threshold`, the round retries with the reduced subset so a single
/// declining voter cannot veto an approved settlement (#1639).
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
    quorum_wallets: Vec<Pubkey>,
    peers: &[(Pubkey, NodeId)],
    threshold: usize,
    send: S,
) -> Result<Transaction>
where
    S: Fn(NodeId, CoSignRequest) -> Fut,
    Fut: Future<Output = Option<CoSignResponse>>,
{
    let mut current_quorum_wallets = quorum_wallets;
    let mut current_peers: Vec<(Pubkey, NodeId)> = peers.to_vec();

    loop {
        if current_quorum_wallets.len() < threshold {
            return Err(BridgeError::Serialization(format!(
                "co-sign quorum not reached: remaining {} signers below threshold {}",
                current_quorum_wallets.len(),
                threshold
            )));
        }

        let payload = CoSignPayload {
            program_id: program_id.to_bytes(),
            authority: leader.pubkey().to_bytes(),
            bridge_vault: bridge_vault.to_bytes(),
            blockhash,
            quorum_validators: current_quorum_wallets.iter().map(|p| p.to_bytes()).collect(),
            params: params.clone(),
        };

        let message = build_settlement_message(&payload)?;
        let own_sig = leader.sign_message(&message.serialize()).as_ref().to_vec();

        let message_bytes = message.serialize();
        if !signature_is_valid(&leader.pubkey(), &own_sig, &message_bytes) {
            return Err(BridgeError::Serialization(
                "leader's own co-sign signature does not verify".to_string(),
            ));
        }

        let request = CoSignRequest {
            request_id: request_id.to_string(),
            kind,
            message: payload.to_bytes()?,
        };

        let mut collected: HashMap<Pubkey, Vec<u8>> = HashMap::new();
        collected.insert(leader.pubkey(), own_sig);

        let mut responsive_peers = Vec::new();
        for (wallet, peer) in &current_peers {
            if let Some(response) = send(peer.clone(), request.clone()).await {
                if let (Some(sig), Ok(resp_wallet)) = (
                    response.signature,
                    response.wallet_pubkey.parse::<Pubkey>(),
                ) {
                    if &resp_wallet == wallet
                        && !collected.contains_key(&resp_wallet)
                        && signature_is_valid(&resp_wallet, &sig, &message_bytes)
                    {
                        collected.insert(resp_wallet, sig);
                        responsive_peers.push((*wallet, peer.clone()));
                    }
                }
            }
        }

        if collected.len() == current_quorum_wallets.len() {
            return assemble_transaction(message, &collected);
        }

        if collected.len() < threshold {
            return Err(BridgeError::Serialization(format!(
                "co-sign quorum not reached: {} of {} signatures",
                collected.len(),
                threshold
            )));
        }

        log::info!(
            "Co-sign round: {} of {} signers responded (threshold={}); retrying with reduced subset",
            collected.len(),
            current_quorum_wallets.len(),
            threshold
        );

        let mut new_wallets = vec![leader.pubkey()];
        new_wallets.extend(responsive_peers.iter().map(|(w, _)| *w));
        current_quorum_wallets = new_wallets;
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
    async fn settles_when_declining_co_signer_leaves_threshold_intact() {
        let leader = Keypair::new();
        let p1 = Arc::new(Keypair::new());
        let p2 = Arc::new(Keypair::new());

        let quorum_wallets = vec![leader.pubkey(), p1.pubkey(), p2.pubkey()];
        let peers = vec![
            (p1.pubkey(), NodeId(vec![1])),
            (p2.pubkey(), NodeId(vec![2])),
        ];

        // 3 wallets offered, threshold is 2. p2 declines.
        // Round should retry reduced with [leader, p1] and assemble successfully (#1639).
        let p1_cloned = p1.clone();
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
            move |peer, request| {
                let p1 = p1_cloned.clone();
                async move {
                    if peer == NodeId(vec![2]) {
                        None // p2 declines
                    } else {
                        Some(honest_response(&p1, &request))
                    }
                }
            },
        )
        .await
        .expect("should succeed with reduced subset when threshold is met");

        assert!(tx.verify().is_ok());
        assert_eq!(tx.signatures.len(), 2);
    }

    #[tokio::test]
    async fn single_declining_co_signer_vetoes_unanimity_round_but_reduced_subset_succeeds() {
        let leader = Keypair::new();
        let p1 = Arc::new(Keypair::new());
        let p2 = Arc::new(Keypair::new()); // small-stake voter that will decline

        let quorum_wallets = vec![leader.pubkey(), p1.pubkey(), p2.pubkey()];
        let peers = vec![
            (p1.pubkey(), NodeId(vec![1])),
            (p2.pubkey(), NodeId(vec![2])),
        ];

        // Unanimity: one decliner fails the round when threshold demands all 3.
        let p1_first = p1.clone();
        let result = run_cosign_round(
            &leader,
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([3u8; 32]),
            [4u8; 32],
            "req-1",
            SettlementKind::Transact,
            transact_params(),
            quorum_wallets.clone(),
            &peers,
            3, // threshold = quorum_wallets.len()
            move |peer, request| {
                let p1 = p1_first.clone();
                async move {
                    if peer == NodeId(vec![2]) {
                        None
                    } else {
                        Some(honest_response(&p1, &request))
                    }
                }
            },
        )
        .await;
        assert!(
            result.is_err(),
            "one declining Valid voter must fail the unanimity round"
        );

        // Control: same settlement over the stake-sufficient subset (leader + p1) assembles fine.
        let p1_second = p1.clone();
        let tx = run_cosign_round(
            &leader,
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([3u8; 32]),
            [4u8; 32],
            "req-1",
            SettlementKind::Transact,
            transact_params(),
            vec![leader.pubkey(), p1.pubkey()],
            &[(p1.pubkey(), NodeId(vec![1]))],
            2,
            move |_peer, request| {
                let p1 = p1_second.clone();
                async move { Some(honest_response(&p1, &request)) }
            },
        )
        .await
        .expect("a stake-sufficient subset must assemble without the decliner");
        assert!(tx.verify().is_ok());
        assert_eq!(tx.signatures.len(), 2);
    }
}
