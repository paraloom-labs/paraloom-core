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
    // To prevent N-of-N unanimity censorship (#1032), we select the required co-signers
    // from the responsive peers up to the threshold rather than binding all valid voters.
    // We try to collect signatures using candidate subsets of size `threshold`, or gather
    // from responsive peers. Since co-signers must sign the byte-identical message whose
    // payload specifies `quorum_validators`, we select the subset of candidate signers
    // (leader + (threshold - 1) peers). If some peers decline or time out, we iterate through
    // combinations or try the responsive subset.
    //
    // Deterministic selection: try candidate subsets of `quorum_wallets` of length `threshold`
    // (starting with the full set if threshold == quorum_wallets.len(), or candidates prioritising
    // responsiveness).
    let leader_pk = leader.pubkey();
    let peer_wallets: Vec<Pubkey> = quorum_wallets
        .iter()
        .filter(|w| **w != leader_pk)
        .copied()
        .collect();

    let peer_threshold = threshold.saturating_sub(1);
    if peer_threshold > peer_wallets.len() {
        return Err(crate::bridge::BridgeError::Serialization(format!(
            "co-sign quorum not reachable: need {} peer signatures but only {} peers available",
            peer_threshold,
            peer_wallets.len()
        )));
    }

    // If threshold matches all quorum wallets, single attempt:
    if peer_threshold == peer_wallets.len() {
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

        return assemble_transaction(message, &collected);
    }

    // When threshold < quorum_wallets.len(), Byzantine peers could decline in a specific subset.
    // Query responsive peers or test candidate subsets of size `threshold`:
    // First, try the first candidate window of size `peer_threshold`. If that fails, try remaining combinations.
    let mut candidate_subsets: Vec<Vec<Pubkey>> = Vec::new();
    // Helper to generate combinations of peer_wallets of length peer_threshold
    fn get_combinations(slice: &[Pubkey], k: usize) -> Vec<Vec<Pubkey>> {
        if k == 0 {
            return vec![vec![]];
        }
        if slice.len() < k {
            return vec![];
        }
        let mut result = Vec::new();
        // Include first element
        for mut sub in get_combinations(&slice[1..], k - 1) {
            let mut v = vec![slice[0]];
            v.append(&mut sub);
            result.push(v);
        }
        // Exclude first element
        for sub in get_combinations(&slice[1..], k) {
            result.push(sub);
        }
        result
    }

    candidate_subsets.extend(get_combinations(&peer_wallets, peer_threshold));

    let mut last_err = None;
    for candidate_peers in candidate_subsets {
        let mut candidate_quorum = vec![leader_pk];
        candidate_quorum.extend(&candidate_peers);

        let payload = CoSignPayload {
            program_id: program_id.to_bytes(),
            authority: leader.pubkey().to_bytes(),
            bridge_vault: bridge_vault.to_bytes(),
            blockhash,
            quorum_validators: candidate_quorum.iter().map(|p| p.to_bytes()).collect(),
            params: params.clone(),
        };

        let message = match build_settlement_message(&payload) {
            Ok(m) => m,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        let own_sig = leader.sign_message(&message.serialize()).as_ref().to_vec();

        let request = CoSignRequest {
            request_id: request_id.to_string(),
            kind,
            message: match payload.to_bytes() {
                Ok(b) => b,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            },
        };

        let candidate_peer_set: std::collections::HashSet<Pubkey> =
            candidate_peers.iter().copied().collect();
        let target_peers: Vec<(Pubkey, NodeId)> = peers
            .iter()
            .filter(|(w, _)| candidate_peer_set.contains(w))
            .cloned()
            .collect();

        match gather_signatures(
            &message,
            (leader.pubkey(), own_sig),
            &target_peers,
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
        .await
        {
            Ok(collected) => return assemble_transaction(message, &collected),
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        crate::bridge::BridgeError::Serialization("co-sign quorum could not be reached".to_string())
    }))
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
    async fn single_declining_voter_breaks_bft_supermajority_round() {
        let leader = Keypair::new();
        let p1 = Keypair::new();
        let p2 = Keypair::new();
        let p3 = Keypair::new();
        let p4_byzantine = Keypair::new();

        let peers = vec![
            (p1.pubkey(), NodeId(vec![1])),
            (p2.pubkey(), NodeId(vec![2])),
            (p3.pubkey(), NodeId(vec![3])),
            (p4_byzantine.pubkey(), NodeId(vec![4])),
        ];
        let mut quorum_wallets = vec![leader.pubkey()];
        quorum_wallets.extend(peers.iter().map(|(w, _)| *w));
        // BFT threshold for 5 validators: floor(2 * 5 / 3) + 1 = 4
        let threshold = 4;

        let result = run_cosign_round(
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
                        _ => None, // Single Byzantine voter withholds CoSignResponse
                    }
                }
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "BFT supermajority (4 of 5) should succeed despite single declining peer, got: {:?}",
            result.err()
        );
        let tx = result.unwrap();
        assert!(tx.verify().is_ok());
        assert_eq!(tx.signatures.len(), 4);
    }
}
