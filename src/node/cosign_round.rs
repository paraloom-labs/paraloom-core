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
    assemble_transaction, build_settlement_message, gather_signatures, CoSignPayload,
    SettlementParams,
};
use crate::bridge::Result;
use crate::network::{CoSignRequest, CoSignResponse, SettlementKind};
use crate::types::NodeId;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::future::Future;

/// Run the leader-side co-signing round and return the assembled, fully-signed
/// settlement transaction (#260).
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
    let payload = CoSignPayload {
        program_id: program_id.to_bytes(),
        authority: leader.pubkey().to_bytes(),
        bridge_vault: bridge_vault.to_bytes(),
        blockhash,
        quorum_validators: quorum_wallets.iter().map(|p| p.to_bytes()).collect(),
        params,
    };

    let message = build_settlement_message(&payload)?;
    let own_sig = leader.sign_message(&message.serialize()).as_ref().to_vec();

    let request = CoSignRequest {
        request_id: request_id.to_string(),
        kind,
        message: payload.to_bytes()?,
    };

    let collected = gather_signatures(
        &message,
        (leader.pubkey(), own_sig),
        peers,
        threshold,
        |peer| {
            let send = &send;
            let request = request.clone();
            let leader_pubkey = leader.pubkey();
            let expected_wallet = peers
                .iter()
                .find(|(_, node_id)| node_id == &peer)
                .map(|(w, _)| *w);
            async move {
                let expected_wallet = expected_wallet?;
                if expected_wallet == leader_pubkey {
                    return None;
                }
                let expected_req_id = request.request_id.clone();
                let response = send(peer, request).await?;
                if response.request_id != expected_req_id {
                    return None;
                }
                let sig = response.signature?;
                let wallet = response.wallet_pubkey.parse::<Pubkey>().ok()?;
                if wallet != expected_wallet {
                    return None;
                }
                Some((wallet, sig))
            }
        },
    )
    .await?;

    assemble_transaction(message, &collected)
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
    async fn rejects_mismatched_request_id_and_unbound_peer_wallet() {
        let leader = Keypair::new();
        let p1 = Keypair::new();
        let p2 = Keypair::new();

        let quorum_wallets = vec![leader.pubkey(), p1.pubkey(), p2.pubkey()];
        let peers = vec![
            (p1.pubkey(), NodeId(vec![1])),
            (p2.pubkey(), NodeId(vec![2])),
        ];

        // Case 1: p1 responds with mismatched request_id ("wrong-req"), p2 responds honestly.
        // Threshold is 3, so rejection of p1 must cause the round to fail.
        let result_bad_req = run_cosign_round(
            &leader,
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([3u8; 32]),
            [4u8; 32],
            "req-1",
            SettlementKind::Transact,
            transact_params(),
            quorum_wallets.clone(),
            &peers,
            3,
            |peer, request| {
                let (p1, p2) = (&p1, &p2);
                async move {
                    if peer == NodeId(vec![1]) {
                        let mut resp = honest_response(p1, &request);
                        resp.request_id = "wrong-req".to_string();
                        Some(resp)
                    } else {
                        Some(honest_response(p2, &request))
                    }
                }
            },
        )
        .await;
        assert!(
            result_bad_req.is_err(),
            "mismatched request_id must be rejected"
        );

        // Case 2: p2 responds with p1's wallet (spoofed / unbound wallet).
        let result_bad_wallet = run_cosign_round(
            &leader,
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([3u8; 32]),
            [4u8; 32],
            "req-1",
            SettlementKind::Transact,
            transact_params(),
            quorum_wallets.clone(),
            &peers,
            3,
            |peer, request| {
                let (p1, p2) = (&p1, &p2);
                async move {
                    if peer == NodeId(vec![1]) {
                        Some(honest_response(p1, &request))
                    } else {
                        // Peer 2 attempts to claim Peer 1's wallet
                        let mut resp = honest_response(p2, &request);
                        resp.wallet_pubkey = p1.pubkey().to_string();
                        Some(resp)
                    }
                }
            },
        )
        .await;
        assert!(
            result_bad_wallet.is_err(),
            "unbound wallet pubkey must be rejected"
        );

        // Case 3: peer wallet configured as leader pubkey is rejected.
        let peers_with_leader = vec![
            (leader.pubkey(), NodeId(vec![1])),
            (p2.pubkey(), NodeId(vec![2])),
        ];
        let result_leader_peer = run_cosign_round(
            &leader,
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([3u8; 32]),
            [4u8; 32],
            "req-1",
            SettlementKind::Transact,
            transact_params(),
            quorum_wallets,
            &peers_with_leader,
            3,
            |peer, request| {
                let (leader, p2) = (&leader, &p2);
                async move {
                    if peer == NodeId(vec![1]) {
                        Some(honest_response(leader, &request))
                    } else {
                        Some(honest_response(p2, &request))
                    }
                }
            },
        )
        .await;
        assert!(
            result_leader_peer.is_err(),
            "peer matching leader pubkey must be rejected"
        );
    }
}
