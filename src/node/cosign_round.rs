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
            async move {
                let response = send(peer, request).await?;
                let sig = response.signature?;
                let wallet = response.wallet_pubkey.parse::<Pubkey>().ok()?;
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
    use crate::node::find_quorum_subsets;

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
    async fn assembles_with_quorum_subset_without_demanding_all_valid_voters() {
        // #1679: When multiple voters approved, the leader assembles a transaction with only
        // a quorum subset as required signers. Other valid voters being offline does not fail
        // the round or invalidate the transaction.
        let leader = Keypair::new();
        let p1 = Keypair::new();
        let _p2 = Keypair::new();

        let program_id = Pubkey::new_from_array([10u8; 32]);
        let vault = Pubkey::new_from_array([11u8; 32]);

        // Leader chooses subset containing only p1, even though p1 and p2 both voted
        let quorum_wallets = vec![leader.pubkey(), p1.pubkey()];
        let subset_peers = vec![(p1.pubkey(), NodeId(vec![1]))];

        // p1 signs, p2 is offline
        let tx = run_cosign_round(
            &leader,
            program_id,
            vault,
            [4u8; 32],
            "req-1679",
            SettlementKind::Transact,
            transact_params(),
            quorum_wallets,
            &subset_peers,
            2,
            |peer, req| {
                let p1_kp = p1.insecure_clone();
                async move {
                    if peer == NodeId(vec![1]) {
                        Some(honest_response(&p1_kp, &req))
                    } else {
                        None
                    }
                }
            },
        )
        .await
        .expect("round with quorum subset must succeed");

        assert_eq!(tx.signatures.len(), 2, "only leader and p1 must be required signers");
        assert!(tx.verify().is_ok(), "the assembled transaction must verify");
    }

    #[tokio::test]
    async fn retries_alternative_candidate_subsets_when_peer_declines() {
        // #1679: When the first candidate subset fails (e.g. peer declines/offline),
        // alternative candidate subsets are attempted and succeed.
        let leader = Keypair::new();
        let p1 = Keypair::new();
        let p2 = Keypair::new();

        let program_id = Pubkey::new_from_array([10u8; 32]);
        let vault = Pubkey::new_from_array([11u8; 32]);

        let peers = vec![
            (p1.pubkey(), NodeId(vec![1]), 0u64),
            (p2.pubkey(), NodeId(vec![2]), 0u64),
        ];

        let candidate_subsets = find_quorum_subsets(&peers, 1, None, 4);
        assert_eq!(candidate_subsets.len(), 3); // [p1], [p2], [p1, p2]

        let mut tx_opt = None;
        for subset in candidate_subsets {
            let mut quorum_wallets = vec![leader.pubkey()];
            quorum_wallets.extend(subset.iter().map(|(w, _)| *w));
            let threshold = quorum_wallets.len();

            let res = run_cosign_round(
                &leader,
                program_id,
                vault,
                [5u8; 32],
                "req-retry",
                SettlementKind::Transact,
                transact_params(),
                quorum_wallets,
                &subset,
                threshold,
                |peer, req| {
                    let p2_kp = p2.insecure_clone();
                    async move {
                        // p1 declines, p2 signs
                        if peer == NodeId(vec![2]) {
                            Some(honest_response(&p2_kp, &req))
                        } else {
                            Some(CoSignResponse {
                                request_id: req.request_id,
                                wallet_pubkey: String::new(),
                                signature: None,
                            })
                        }
                    }
                },
            )
            .await;

            if let Ok(tx) = res {
                tx_opt = Some(tx);
                break;
            }
        }

        let tx = tx_opt.expect("must successfully settle using alternative candidate subset");
        assert_eq!(tx.signatures.len(), 2);
        assert!(tx.verify().is_ok());
    }
}
