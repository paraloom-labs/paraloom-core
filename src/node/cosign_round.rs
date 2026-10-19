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
    let needed_peers = threshold.saturating_sub(1);
    let mut remaining_peers: Vec<(Pubkey, NodeId)> = peers.to_vec();

    loop {
        let cohort_peers: Vec<(Pubkey, NodeId)> = remaining_peers
            .iter()
            .take(needed_peers)
            .cloned()
            .collect();
        let mut cohort_wallets = Vec::with_capacity(1 + cohort_peers.len());
        cohort_wallets.push(leader.pubkey());
        for (w, _) in &cohort_peers {
            if !cohort_wallets.contains(w) {
                cohort_wallets.push(*w);
            }
        }
        // If `peers` is empty but caller passed extra `quorum_wallets`, preserve
        // up to `threshold` wallets so existing error paths behave identically.
        for w in &quorum_wallets {
            if cohort_wallets.len() >= threshold {
                break;
            }
            if !cohort_wallets.contains(w) {
                cohort_wallets.push(*w);
            }
        }

        let payload = CoSignPayload {
            program_id: program_id.to_bytes(),
            authority: leader.pubkey().to_bytes(),
            bridge_vault: bridge_vault.to_bytes(),
            blockhash,
            quorum_validators: cohort_wallets.iter().map(|p| p.to_bytes()).collect(),
            params: params.clone(),
        };

        let message = build_settlement_message(&payload)?;
        let message_bytes = message.serialize();
        let own_sig = leader.sign_message(&message_bytes).as_ref().to_vec();

        let request = CoSignRequest {
            request_id: request_id.to_string(),
            kind,
            message: payload.to_bytes()?,
        };

        let failed_peer: std::sync::Mutex<Option<NodeId>> = std::sync::Mutex::new(None);
        match gather_signatures(
            &message,
            (leader.pubkey(), own_sig),
            &cohort_peers,
            threshold,
            |peer| {
                let send = &send;
                let request = request.clone();
                let failed_peer = &failed_peer;
                let message_bytes = &message_bytes;
                let expected_wallet = cohort_peers
                    .iter()
                    .find(|(_, id)| *id == peer)
                    .map(|(w, _)| *w);
                async move {
                    // Abort remaining requests in this cohort as soon as one
                    // required signer declines, avoiding wasted co-sign budget
                    // on a message whose header includes the declining signer.
                    if failed_peer.lock().unwrap().is_some() {
                        return None;
                    }
                    let record_failure = || {
                        *failed_peer.lock().unwrap() = Some(peer.clone());
                        None
                    };
                    let Some(response) = send(peer.clone(), request).await else {
                        return record_failure();
                    };
                    let Some(sig) = response.signature else {
                        return record_failure();
                    };
                    let Ok(wallet) = response.wallet_pubkey.parse::<Pubkey>() else {
                        return record_failure();
                    };
                    if expected_wallet.is_some_and(|exp| exp != wallet) {
                        return record_failure();
                    }
                    if !crate::bridge::solana::cosign_assembly::signature_is_valid(
                        &wallet,
                        &sig,
                        message_bytes,
                    ) {
                        return record_failure();
                    }
                    Some((wallet, sig))
                }
            },
        )
        .await
        {
            Ok(collected) => return assemble_transaction(message, &collected),
            Err(e) => {
                if let Some(bad) = failed_peer.into_inner().unwrap() {
                    remaining_peers.retain(|(_, id)| *id != bad);
                    if 1 + remaining_peers.len() >= threshold {
                        continue;
                    }
                }
                return Err(e);
            }
        }
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
    async fn single_declining_voter_does_not_break_bft_supermajority_round() {
        let leader = Keypair::new();
        let p1 = Keypair::new();
        let p2 = Keypair::new();
        let p3 = Keypair::new();
        let p4_byzantine = Keypair::new();

        // Put the Byzantine voter first to exercise cohort eviction + retry
        // without wasting the honest peers' co-sign budget on the failed cohort.
        let peers = vec![
            (p4_byzantine.pubkey(), NodeId(vec![4])),
            (p1.pubkey(), NodeId(vec![1])),
            (p2.pubkey(), NodeId(vec![2])),
            (p3.pubkey(), NodeId(vec![3])),
        ];
        let mut quorum_wallets = vec![leader.pubkey()];
        quorum_wallets.extend(peers.iter().map(|(w, _)| *w));
        let threshold = 4; // BFT supermajority of 5 validators: floor(2*5/3) + 1 = 4

        let tx = run_cosign_round(
            &leader,
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([3u8; 32]),
            [4u8; 32],
            "req-bft",
            SettlementKind::Transact,
            transact_params(),
            quorum_wallets,
            &peers,
            threshold,
            |peer, request| {
                let (p1, p2, p3) = (&p1, &p2, &p3);
                async move {
                    match peer.0.as_slice() {
                        [1] => Some(honest_response(p1, &request)),
                        [2] => Some(honest_response(p2, &request)),
                        [3] => Some(honest_response(p3, &request)),
                        _ => None, // Byzantine voter withholds CoSignResponse
                    }
                }
            },
        )
        .await
        .expect("4-of-5 BFT supermajority succeeds despite 1 declining voter");

        assert!(tx.verify().is_ok());
        assert_eq!(tx.signatures.len(), 4);
    }
}
