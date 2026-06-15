//! Leader-side signature collection and multi-signature assembly for the
//! co-signing round (#260).
//!
//! The round leader holds the settlement [`Message`] (built deterministically
//! from a `CoSignPayload`) and its own signature over it. It asks each other
//! approving validator to co-sign the same message and assembles the collected
//! signatures into one fully-signed [`Transaction`] that satisfies the on-chain
//! validator quorum.
//!
//! Both steps are pure and injectable so they can be unit-tested without a
//! network: [`gather_signatures`] takes a request closure, and
//! [`assemble_transaction`] takes a signature map.

use crate::bridge::{BridgeError, Result};
use crate::types::NodeId;
use solana_sdk::{
    message::Message, pubkey::Pubkey, signature::Signature, transaction::Transaction,
};
use std::collections::HashMap;
use std::future::Future;

/// Collect co-signatures for `message` until `threshold` distinct, verified
/// signatures are held (#260).
///
/// Seeded with the leader's own `(wallet, signature)`. For each other approving
/// validator it calls `request(peer)`; a returned `(wallet, signature)` is kept
/// only if the wallet is one of the expected `peers`, the signature verifies
/// over `message`, and the wallet is not already counted. Stops as soon as the
/// threshold is reached; errors if the peers are exhausted first.
///
/// `request` is injectable (the node wires it to the co-sign network protocol;
/// tests pass a mock), and returning `None` models a decline or timeout.
pub async fn gather_signatures<F, Fut>(
    message: &Message,
    own: (Pubkey, Vec<u8>),
    peers: &[(Pubkey, NodeId)],
    threshold: usize,
    request: F,
) -> Result<HashMap<Pubkey, Vec<u8>>>
where
    F: Fn(NodeId) -> Fut,
    Fut: Future<Output = Option<(Pubkey, Vec<u8>)>>,
{
    let message_bytes = message.serialize();
    let expected: std::collections::HashSet<Pubkey> = peers.iter().map(|(w, _)| *w).collect();

    let mut collected: HashMap<Pubkey, Vec<u8>> = HashMap::new();
    // The leader's own signature is trusted but still verified, so a wiring bug
    // can never assemble a transaction that fails on submit.
    if !signature_is_valid(&own.0, &own.1, &message_bytes) {
        return Err(BridgeError::Serialization(
            "leader's own co-sign signature does not verify".to_string(),
        ));
    }
    collected.insert(own.0, own.1);

    for (_, peer) in peers {
        if collected.len() >= threshold {
            break;
        }
        let Some((wallet, sig)) = request(peer.clone()).await else {
            continue; // declined or timed out
        };
        if !expected.contains(&wallet) || collected.contains_key(&wallet) {
            continue; // unexpected or duplicate signer
        }
        if !signature_is_valid(&wallet, &sig, &message_bytes) {
            log::warn!("co-sign signature from {wallet} did not verify; ignoring");
            continue;
        }
        collected.insert(wallet, sig);
    }

    if collected.len() < threshold {
        return Err(BridgeError::Serialization(format!(
            "co-sign quorum not reached: {} of {} signatures",
            collected.len(),
            threshold
        )));
    }
    Ok(collected)
}

/// Assemble a fully-signed [`Transaction`] from per-wallet signatures (#260).
///
/// Each of the message's required-signer accounts (the leading
/// `num_required_signatures` of `account_keys`) must have a signature in
/// `signatures`, keyed by that account's pubkey and produced over
/// `message.serialize()`. Signatures are placed in signer-account order, as the
/// runtime expects. Errors if any required signer is missing or malformed, or
/// if the assembled transaction fails to verify.
pub fn assemble_transaction(
    message: Message,
    signatures: &HashMap<Pubkey, Vec<u8>>,
) -> Result<Transaction> {
    let num_signers = message.header.num_required_signatures as usize;
    let mut ordered = Vec::with_capacity(num_signers);
    for key in &message.account_keys[..num_signers] {
        let sig_bytes = signatures.get(key).ok_or_else(|| {
            BridgeError::Serialization(format!("missing co-signature for required signer {key}"))
        })?;
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|_| BridgeError::Serialization(format!("malformed signature for {key}")))?;
        ordered.push(sig);
    }

    let tx = Transaction {
        signatures: ordered,
        message,
    };
    tx.verify().map_err(|e| {
        BridgeError::Serialization(format!("assembled transaction failed to verify: {e}"))
    })?;
    Ok(tx)
}

/// Whether `sig_bytes` is a valid signature by `wallet` over `message_bytes`.
fn signature_is_valid(wallet: &Pubkey, sig_bytes: &[u8], message_bytes: &[u8]) -> bool {
    match Signature::try_from(sig_bytes) {
        Ok(sig) => sig.verify(wallet.as_ref(), message_bytes),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::{Keypair, Signer};
    use solana_sdk::system_instruction;

    /// A simple 2-signer message: a transfer requiring both `a` (payer) and a
    /// second signer. Enough to exercise multi-signature ordering without
    /// pulling in the paraloom program.
    fn two_signer_message(a: &Pubkey, b: &Pubkey) -> Message {
        // An instruction that marks both accounts as signers.
        let ix = system_instruction::transfer(a, b, 1);
        let mut msg = Message::new(&[ix], Some(a));
        // `transfer` marks the recipient writable-non-signer; force b to be a
        // required signer so we get a genuine 2-of-2.
        msg.header.num_required_signatures = 2;
        // Ensure b sits in the signer region (it already follows a as account 1).
        msg
    }

    fn sign(kp: &Keypair, message: &Message) -> (Pubkey, Vec<u8>) {
        let sig = kp.sign_message(&message.serialize());
        (kp.pubkey(), sig.as_ref().to_vec())
    }

    #[test]
    fn assembles_a_fully_signed_transaction() {
        let a = Keypair::new();
        let b = Keypair::new();
        let message = two_signer_message(&a.pubkey(), &b.pubkey());

        let mut sigs = HashMap::new();
        let (wa, sa) = sign(&a, &message);
        let (wb, sb) = sign(&b, &message);
        sigs.insert(wa, sa);
        sigs.insert(wb, sb);

        let tx = assemble_transaction(message, &sigs).expect("assemble");
        assert!(tx.verify().is_ok(), "assembled tx must verify");
    }

    #[test]
    fn assembly_fails_when_a_required_signer_is_missing() {
        let a = Keypair::new();
        let b = Keypair::new();
        let message = two_signer_message(&a.pubkey(), &b.pubkey());

        let mut sigs = HashMap::new();
        let (wa, sa) = sign(&a, &message);
        sigs.insert(wa, sa); // b's signature withheld

        assert!(assemble_transaction(message, &sigs).is_err());
    }

    #[tokio::test]
    async fn gathers_signatures_up_to_the_threshold() {
        let leader = Keypair::new();
        let v1 = Keypair::new();
        let v2 = Keypair::new();
        let message = two_signer_message(&leader.pubkey(), &v1.pubkey());

        let own = sign(&leader, &message);
        let peers = vec![
            (v1.pubkey(), NodeId(vec![1])),
            (v2.pubkey(), NodeId(vec![2])),
        ];

        // Both peers co-sign; threshold of 2 (leader + one) is reached.
        let msg_for_closure = message.clone();
        let collected = gather_signatures(&message, own, &peers, 2, |peer| {
            let message = msg_for_closure.clone();
            let (v1, v2) = (&v1, &v2);
            async move {
                let kp = if peer == NodeId(vec![1]) { v1 } else { v2 };
                Some(sign(kp, &message))
            }
        })
        .await
        .expect("threshold reached");
        assert!(collected.len() >= 2);
    }

    #[tokio::test]
    async fn gather_errors_when_threshold_not_reached() {
        let leader = Keypair::new();
        let v1 = Keypair::new();
        let message = two_signer_message(&leader.pubkey(), &v1.pubkey());
        let own = sign(&leader, &message);
        let peers = vec![(v1.pubkey(), NodeId(vec![1]))];

        // The only peer declines, so we cannot reach a threshold of 2.
        let result = gather_signatures(&message, own, &peers, 2, |_peer| async { None }).await;
        assert!(result.is_err(), "must error when the quorum is not reached");
    }

    #[tokio::test]
    async fn gather_rejects_an_invalid_signature() {
        let leader = Keypair::new();
        let v1 = Keypair::new();
        let imposter = Keypair::new();
        let message = two_signer_message(&leader.pubkey(), &v1.pubkey());
        let own = sign(&leader, &message);
        let peers = vec![(v1.pubkey(), NodeId(vec![1]))];

        // The peer returns v1's wallet but a signature from a different key:
        // it must be rejected, leaving the threshold unmet.
        let msg = message.clone();
        let result = gather_signatures(&message, own, &peers, 2, |_peer| {
            let msg = msg.clone();
            let imposter = &imposter;
            let v1_wallet = v1.pubkey();
            async move {
                let bad = imposter.sign_message(&msg.serialize());
                Some((v1_wallet, bad.as_ref().to_vec()))
            }
        })
        .await;
        assert!(
            result.is_err(),
            "a forged signature must not count toward the quorum"
        );
    }
}
