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
///   (the on-chain quorum size). If some peers decline or time out but the
///   collected count satisfies `threshold`, the round re-assembles with the
///   responsive co-signer subset (#1504).
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
    let expected: std::collections::HashSet<Pubkey> = peers.iter().map(|(w, _)| *w).collect();

    let mut collected: std::collections::HashMap<Pubkey, Vec<u8>> =
        std::collections::HashMap::new();
    if !crate::bridge::solana::cosign_assembly::signature_is_valid(
        &leader.pubkey(),
        &own_sig,
        &message_bytes,
    ) {
        return Err(crate::bridge::BridgeError::Serialization(
            "leader's own co-sign signature does not verify".to_string(),
        ));
    }
    collected.insert(leader.pubkey(), own_sig);

    for (_, peer) in peers {
        let Some(response) = send(peer.clone(), request.clone()).await else {
            continue; // declined or timed out
        };
        let Some(sig) = response.signature else {
            continue;
        };
        let Ok(wallet) = response.wallet_pubkey.parse::<Pubkey>() else {
            continue;
        };
        if !expected.contains(&wallet) || collected.contains_key(&wallet) {
            continue;
        }
        if !crate::bridge::solana::cosign_assembly::signature_is_valid(
            &wallet,
            &sig,
            &message_bytes,
        ) {
            log::warn!("co-sign signature from {wallet} did not verify; ignoring");
            continue;
        }
        collected.insert(wallet, sig);
    }

    if collected.len() < threshold {
        return Err(crate::bridge::BridgeError::Serialization(format!(
            "co-sign quorum not reached: {} of {} signatures",
            collected.len(),
            threshold
        )));
    }

    if collected.len() < quorum_wallets.len() {
        // A subset of peers declined or timed out, but the collected signatures
        // meet or exceed the on-chain threshold (#1504). Re-assemble with the
        // responsive co-signer subset so the transaction does not require missing signatures.
        let responsive_wallets: Vec<Pubkey> = quorum_wallets
            .iter()
            .copied()
            .filter(|w| collected.contains_key(w))
            .collect();
        let responsive_peers: Vec<(Pubkey, NodeId)> = peers
            .iter()
            .filter(|(w, _)| collected.contains_key(w))
            .cloned()
            .collect();

        let fallback_payload = CoSignPayload {
            program_id: program_id.to_bytes(),
            authority: leader.pubkey().to_bytes(),
            bridge_vault: bridge_vault.to_bytes(),
            blockhash,
            quorum_validators: responsive_wallets.iter().map(|p| p.to_bytes()).collect(),
            params,
        };

        let fallback_message = build_settlement_message(&fallback_payload)?;
        let fallback_own_sig = leader
            .sign_message(&fallback_message.serialize())
            .as_ref()
            .to_vec();
        let fallback_request = CoSignRequest {
            request_id: request_id.to_string(),
            kind,
            message: fallback_payload.to_bytes()?,
        };

        let fallback_collected = gather_signatures(
            &fallback_message,
            (leader.pubkey(), fallback_own_sig),
            &responsive_peers,
            responsive_wallets.len(),
            |peer| {
                let send = &send;
                let request = fallback_request.clone();
                async move {
                    let response = send(peer, request).await?;
                    let sig = response.signature?;
                    let wallet = response.wallet_pubkey.parse::<Pubkey>().ok()?;
                    Some((wallet, sig))
                }
            },
        )
        .await?;

        assemble_transaction(fallback_message, &fallback_collected)
    } else {
        assemble_transaction(message, &collected)
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
    async fn assembles_transaction_when_co_signer_declines_but_threshold_is_met() {
        let leader = Keypair::new();
        let p1 = Keypair::new();
        let p2 = Keypair::new();

        // 3 validators in the quorum, but threshold is 2 (2/3 quorum: leader + 1 peer) (#1504).
        let quorum_wallets = vec![leader.pubkey(), p1.pubkey(), p2.pubkey()];
        let peers = vec![
            (p1.pubkey(), NodeId(vec![1])),
            (p2.pubkey(), NodeId(vec![2])),
        ];

        // p1 co-signs, but p2 declines/refuses.
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
                        None // p2 refuses to co-sign
                    }
                }
            },
        )
        .await
        .expect("round completes with fallback responsive subset");

        assert!(
            tx.verify().is_ok(),
            "the fallback assembled transaction must verify"
        );
        assert_eq!(
            tx.signatures.len(),
            2,
            "leader plus the responsive co-signer must have signed"
        );
    }
}
