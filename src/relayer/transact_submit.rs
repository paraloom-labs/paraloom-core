//! Shared v3 `transact` + `deposit_note` settlement helpers for the private-swap
//! relayer, factored out of the `demo-transact-v3` driver (#350) so the demo,
//! the `OnChainSubmitter`, and the private-swap e2e all settle the *same* way.
//!
//! The relayer's withdraw-to-fresh leg is a v3 `transact` with `ext_amount < 0`
//! and `recipient = fresh_address`: it spends one real note plus a zero-value
//! dummy input, emits two zero-value output notes (full withdrawal, no change),
//! and pays `amount - fee` lamports to the fresh address. Settlement is not a
//! direct RPC transaction — the tagged proof + params are POSTed to the public
//! transact ingress and the 2-of-2 validator quorum co-signs and settles it
//! on-chain, so these helpers submit over HTTP and then poll on-chain for the
//! result. The re-shield leg is a plain permissionless `deposit_note`.
//!
//! Blocking on purpose: the on-chain reads use `solana_client`'s blocking
//! `RpcClient` and the ingress POST uses `reqwest::blocking`, exactly as the
//! proven demo does. The async `OnChainSubmitter` calls these from
//! `tokio::task::spawn_blocking`.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use base64::Engine as _;
use solana_client::{
    rpc_client::{GetConfirmedSignaturesForAddress2Config, RpcClient},
    rpc_config::RpcTransactionConfig,
};
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature,
};
use solana_transaction_status::{option_serializer::OptionSerializer, UiTransactionEncoding};
use std::{str::FromStr, time::Duration};

use crate::bridge::solana::{derive_nullifier_account, derive_validator_registry};
use crate::privacy::circuits::{Groth16ProofSystem, TransactCircuitV3, TX_LEVELS};
use crate::privacy::poseidon_circom::{
    v3_commit, v3_merkle_pair, v3_nullifier, v3_pubkey, v3_signature,
};
use crate::privacy::{tag_proof, ProofSuite, ProofVerifier};

/// Errors from the shared v3 settlement helpers.
#[derive(Debug, thiserror::Error)]
pub enum TransactSubmitError {
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("merkle path does not fold to the on-chain root (leaf {leaf_index})")]
    RootMismatch { leaf_index: u64 },
    #[error("proving failed: {0}")]
    Prove(String),
    #[error("proof self-verification failed (proving/verifying key mismatch?): {0}")]
    SelfVerify(String),
    #[error("ingress rejected the transact: {status} {body}")]
    IngressRejected { status: u16, body: String },
    #[error("http error talking to the ingress: {0}")]
    Http(String),
    #[error("settlement did not land within {0:?}")]
    SettlementTimeout(Duration),
    #[error("account data too short: {0}")]
    ShortAccount(&'static str),
}

pub type Result<T> = std::result::Result<T, TransactSubmitError>;

fn fr_to_le(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let le = f.into_bigint().to_bytes_le();
    out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    out
}

fn rand_fr() -> Fr {
    use ark_std::rand::RngCore;
    let mut b = [0u8; 32];
    ark_std::rand::thread_rng().fill_bytes(&mut b);
    b[31] &= 0x1f;
    Fr::from_le_bytes_mod_order(&b)
}

/// A leaf's authentication path against the current on-chain incremental tree.
pub struct Membership {
    pub leaf_index: u64,
    /// On-chain root the path folds to (LE field bytes).
    pub root: [u8; 32],
    /// Sibling hashes level 0..TX_LEVELS (LE field bytes).
    pub path: Vec<[u8; 32]>,
}

/// Anchor event discriminators (`sha256("event:<Name>")[..8]`) emitted by the
/// on-chain program whenever leaves are appended to the v3 incremental tree.
const DEPOSIT_NOTE_EVENT_DISCRIMINATOR: [u8; 8] = [85, 20, 187, 76, 92, 196, 249, 195];
const DEPOSIT_NOTE_SPL_EVENT_DISCRIMINATOR: [u8; 8] = [229, 33, 39, 208, 18, 5, 237, 1];
const TRANSACT_EVENT_DISCRIMINATOR: [u8; 8] = [89, 245, 87, 250, 222, 30, 135, 142];

/// Fast-path membership reconstruction from the on-chain `merkle_tree` account's
/// `filled_subtrees` + zero-subtree hashes.
///
/// Because `filled_subtrees[level]` only holds the left sibling of the most
/// recently appended leaf (`next_index - 1`) and right siblings are only
/// `zeros[level]` when no leaf has been appended to the right of `leaf_index`,
/// this fast path only folds to `root_onchain` when `leaf_index == next_index - 1`.
/// For any earlier leaf (`leaf_index < next_index - 1`), it returns
/// [`TransactSubmitError::RootMismatch`] so [`read_membership`] can fall back to
/// rebuilding the full tree from the program's event logs.
pub fn membership_from_tree_account(
    raw: &[u8],
    leaf_index: u64,
    commitment: Fr,
) -> Result<Membership> {
    if raw.len() < 56 + TX_LEVELS * 32 {
        return Err(TransactSubmitError::ShortAccount("merkle_tree"));
    }
    let root_onchain: [u8; 32] = raw[24..56]
        .try_into()
        .map_err(|_| TransactSubmitError::ShortAccount("merkle_tree root"))?;

    let mut zeros = vec![Fr::from(0u64)];
    for k in 0..TX_LEVELS {
        zeros.push(v3_merkle_pair(zeros[k], zeros[k]));
    }
    let mut path: Vec<[u8; 32]> = Vec::with_capacity(TX_LEVELS);
    #[allow(clippy::needless_range_loop)]
    for level in 0..TX_LEVELS {
        let sib = if (leaf_index >> level) & 1 == 1 {
            let off = 56 + level * 32;
            let fs: [u8; 32] = raw[off..off + 32]
                .try_into()
                .map_err(|_| TransactSubmitError::ShortAccount("filled_subtrees"))?;
            fs
        } else {
            fr_to_le(&zeros[level])
        };
        path.push(sib);
    }

    // Fold to confirm the path matches the on-chain root before we prove.
    let mut cur = commitment;
    for (level, sib) in path.iter().enumerate() {
        let s = Fr::from_le_bytes_mod_order(sib);
        cur = if (leaf_index >> level) & 1 == 1 {
            v3_merkle_pair(s, cur)
        } else {
            v3_merkle_pair(cur, s)
        };
    }
    if fr_to_le(&cur) != root_onchain {
        return Err(TransactSubmitError::RootMismatch { leaf_index });
    }

    Ok(Membership {
        leaf_index,
        root: root_onchain,
        path,
    })
}

/// Reconstruct `leaf_index`'s 32-level v3 Poseidon authentication path from the
/// ordered list of all leaves `leaves[0..N]` in the incremental tree, verifying
/// that the resulting root matches `expected_root`.
///
/// Works for arbitrary `leaf_index < leaves.len()`, including notes created
/// before subsequent deposits or transacts advanced the tree.
pub fn membership_from_leaves(
    leaves: &[[u8; 32]],
    leaf_index: u64,
    commitment: Fr,
    expected_root: &[u8; 32],
) -> Result<Membership> {
    let idx0 = usize::try_from(leaf_index)
        .map_err(|_| TransactSubmitError::RootMismatch { leaf_index })?;
    if idx0 >= leaves.len() || leaves[idx0] != fr_to_le(&commitment) {
        return Err(TransactSubmitError::RootMismatch { leaf_index });
    }

    let mut zeros = vec![Fr::from(0u64)];
    for k in 0..TX_LEVELS {
        zeros.push(v3_merkle_pair(zeros[k], zeros[k]));
    }

    let mut nodes: Vec<Fr> = leaves
        .iter()
        .map(|b| Fr::from_le_bytes_mod_order(b))
        .collect();
    let mut path: Vec<[u8; 32]> = Vec::with_capacity(TX_LEVELS);
    let mut idx = idx0;

    for level in 0..TX_LEVELS {
        let sib_idx = idx ^ 1;
        let sib_fr = nodes.get(sib_idx).copied().unwrap_or(zeros[level]);
        path.push(fr_to_le(&sib_fr));

        let next_len = nodes.len().div_ceil(2);
        let mut next = Vec::with_capacity(next_len);
        for i in 0..next_len {
            let left = nodes[2 * i];
            let right = nodes.get(2 * i + 1).copied().unwrap_or(zeros[level]);
            next.push(v3_merkle_pair(left, right));
        }
        nodes = next;
        idx >>= 1;
    }

    let computed_root = nodes.first().copied().unwrap_or(zeros[TX_LEVELS]);
    if fr_to_le(&computed_root) != *expected_root {
        return Err(TransactSubmitError::RootMismatch { leaf_index });
    }

    Ok(Membership {
        leaf_index,
        root: *expected_root,
        path,
    })
}

/// Extract base64-decoded `Program data:` payloads emitted while
/// `expected_program_id` is on top of the Solana CPI invoke stack.
fn extract_event_payloads(logs: &[String], expected_program_id: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut stack: Vec<&str> = Vec::new();
    for line in logs {
        if let Some(rest) = line.strip_prefix("Program ") {
            if let Some((prog, _)) = rest.split_once(" invoke [") {
                stack.push(prog);
                continue;
            }
            if rest.ends_with(" success") || rest.contains(" failed:") {
                stack.pop();
                continue;
            }
        }
        if let Some(b64) = line.strip_prefix("Program data: ") {
            if stack.last().copied() == Some(expected_program_id) {
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                    out.push(bytes);
                }
            }
        }
    }
    out
}

/// Parse ordered `(leaf_index, commitment)` pairs from a sequence of
/// transaction log-message slices in chronological (oldest-first) order.
fn parse_leaves_from_tx_logs(
    tx_logs_oldest_first: &[Vec<String>],
    expected_program_id: &str,
) -> Vec<(u64, [u8; 32])> {
    let mut leaves: Vec<(u64, [u8; 32])> = Vec::new();
    let mut transact_cursor: Option<u64> = None;

    for logs in tx_logs_oldest_first {
        for payload in extract_event_payloads(logs, expected_program_id) {
            if payload.starts_with(&DEPOSIT_NOTE_EVENT_DISCRIMINATOR) && payload.len() >= 8 + 80 {
                let body = &payload[8..];
                let commitment: [u8; 32] = body[40..72].try_into().expect("32-byte slice");
                let idx = u64::from_le_bytes(body[72..80].try_into().expect("8-byte slice"));
                leaves.push((idx, commitment));
                transact_cursor = Some(transact_cursor.unwrap_or(0).max(idx + 1));
            } else if payload.starts_with(&DEPOSIT_NOTE_SPL_EVENT_DISCRIMINATOR)
                && payload.len() >= 8 + 112
            {
                let body = &payload[8..];
                let commitment: [u8; 32] = body[72..104].try_into().expect("32-byte slice");
                let idx = u64::from_le_bytes(body[104..112].try_into().expect("8-byte slice"));
                leaves.push((idx, commitment));
                transact_cursor = Some(transact_cursor.unwrap_or(0).max(idx + 1));
            } else if payload.starts_with(&TRANSACT_EVENT_DISCRIMINATOR)
                && payload.len() >= 8 + 128
            {
                let body = &payload[8..];
                let oc0: [u8; 32] = body[64..96].try_into().expect("32-byte slice");
                let oc1: [u8; 32] = body[96..128].try_into().expect("32-byte slice");
                let base = transact_cursor.unwrap_or(leaves.len() as u64);
                leaves.push((base, oc0));
                leaves.push((base + 1, oc1));
                transact_cursor = Some(base + 2);
            }
        }
    }

    leaves.sort_by_key(|(idx, _)| *idx);
    leaves
}

/// Fetch the full ordered v3 leaf list from the program's on-chain event logs
/// (`DepositNoteEvent`, `DepositNoteSplEvent`, `TransactEvent`), matching the
/// wallet's `fetchV3Leaves` reconstruction.
fn fetch_v3_leaves(client: &RpcClient, program_id: &Pubkey) -> Result<Vec<[u8; 32]>> {
    let mut sigs = Vec::new();
    let mut before: Option<Signature> = None;
    loop {
        let page = client
            .get_signatures_for_address_with_config(
                program_id,
                GetConfirmedSignaturesForAddress2Config {
                    before,
                    until: None,
                    limit: Some(1000),
                    commitment: Some(CommitmentConfig::confirmed()),
                },
            )
            .map_err(|e| TransactSubmitError::Rpc(e.to_string()))?;
        if page.is_empty() {
            break;
        }
        let last_sig = page
            .last()
            .and_then(|s| Signature::from_str(&s.signature).ok());
        let short_page = page.len() < 1000;
        sigs.extend(page);
        if short_page || last_sig.is_none() {
            break;
        }
        before = last_sig;
    }

    let expected_prog = program_id.to_string();
    let mut tx_logs_oldest_first: Vec<Vec<String>> = Vec::new();
    for sig_info in sigs.iter().rev() {
        if sig_info.err.is_some() {
            continue;
        }
        let sig = Signature::from_str(&sig_info.signature)
            .map_err(|e| TransactSubmitError::Rpc(e.to_string()))?;
        let mut tx_res = None;
        for _ in 0..3 {
            if let Ok(tx) = client.get_transaction_with_config(
                &sig,
                RpcTransactionConfig {
                    encoding: Some(UiTransactionEncoding::Json),
                    commitment: Some(CommitmentConfig::confirmed()),
                    max_supported_transaction_version: Some(0),
                },
            ) {
                tx_res = Some(tx);
                break;
            }
        }
        let tx = tx_res.ok_or_else(|| {
            TransactSubmitError::Rpc(format!("getTransaction failed after retries for {sig}"))
        })?;
        if let Some(meta) = tx.transaction.meta {
            if let OptionSerializer::Some(logs) = meta.log_messages {
                tx_logs_oldest_first.push(logs);
            }
        }
    }

    let indexed = parse_leaves_from_tx_logs(&tx_logs_oldest_first, &expected_prog);
    let mut out = Vec::with_capacity(indexed.len());
    for (pos, (idx, commitment)) in indexed.into_iter().enumerate() {
        if idx != pos as u64 {
            return Err(TransactSubmitError::Rpc(format!(
                "non-contiguous v3 leaf history at position {pos} (saw index {idx})"
            )));
        }
        out.push(commitment);
    }
    Ok(out)
}

/// Read the on-chain merkle tree and reconstruct `leaf_index`'s authentication
/// path.
///
/// First attempts the single-account fast path (`filled_subtrees` +
/// zero-subtree hashes), which succeeds in one RPC call when `leaf_index` is
/// the most recently appended leaf (`leaf_index == next_index - 1`). When sub-
/// sequent deposits or transacts have advanced the tree past `leaf_index`,
/// `filled_subtrees` + `zeros` no longer represents `leaf_index`'s siblings;
/// `read_membership` then falls back to rebuilding the ordered v3 leaf set from
/// the program's event logs and folding the exact authentication path against
/// `root_onchain`.
///
/// Tree account layout: disc(8) | next_index(8) | root_index(8) | root(32) |
/// `filled_subtrees[TX_LEVELS][32]` (from offset 56).
pub fn read_membership(
    client: &RpcClient,
    program_id: &Pubkey,
    leaf_index: u64,
    commitment: Fr,
) -> Result<Membership> {
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], program_id);
    let raw = client
        .get_account_data(&tree_pda)
        .map_err(|e| TransactSubmitError::Rpc(e.to_string()))?;
    if raw.len() < 56 + TX_LEVELS * 32 {
        return Err(TransactSubmitError::ShortAccount("merkle_tree"));
    }
    if let Ok(m) = membership_from_tree_account(&raw, leaf_index, commitment) {
        return Ok(m);
    }

    let root_onchain: [u8; 32] = raw[24..56]
        .try_into()
        .map_err(|_| TransactSubmitError::ShortAccount("merkle_tree root"))?;
    let leaves = fetch_v3_leaves(client, program_id)?;
    membership_from_leaves(&leaves, leaf_index, commitment, &root_onchain)
}

/// The tagged proof + on-chain public parts of a withdraw-to-fresh v3 transact.
pub struct WithdrawToFresh {
    /// Tagged (`Groth16Bn254TransactV3`) wire proof.
    pub proof: Vec<u8>,
    pub nullifiers: [[u8; 32]; 2],
    pub output_commitments: [[u8; 32]; 2],
    pub root: [u8; 32],
    /// Negative: `-(amount)`.
    pub ext_amount: i64,
}

/// Prove a full withdrawal of `amount` lamports of a native-SOL note (spend key
/// `sk`, `blinding`, at `membership.leaf_index`) to `recipient` (a fresh 32-byte
/// address). Spends the real note + a zero dummy input, emits two zero-value
/// output notes to `note_pubkey` (no change). Mirrors `demo-transact-v3` exactly
/// so the node's `verify_transact_parts` accepts it bit-for-bit.
#[allow(clippy::too_many_arguments)]
pub fn prove_withdraw_to_fresh(
    proving_key: &ark_groth16::ProvingKey<ark_bn254::Bn254>,
    sk: Fr,
    blinding: Fr,
    note_pubkey: Fr,
    amount: u64,
    membership: &Membership,
    recipient: &[u8; 32],
) -> Result<WithdrawToFresh> {
    let root = Fr::from_le_bytes_mod_order(&membership.root);
    let commitment = v3_commit(Fr::from(amount), note_pubkey, blinding, Fr::from(0u64));
    let leaf_index = membership.leaf_index;

    let sig0 = v3_signature(sk, commitment, Fr::from(leaf_index));
    let nf0 = v3_nullifier(commitment, Fr::from(leaf_index), sig0);
    // Zero-value dummy input (membership skipped in-circuit for a zero note).
    let dsk = rand_fr();
    let dbl = rand_fr();
    let dc = v3_commit(Fr::from(0u64), v3_pubkey(dsk), dbl, Fr::from(0u64));
    let dsig = v3_signature(dsk, dc, Fr::from(0u64));
    let nf1 = v3_nullifier(dc, Fr::from(0u64), dsig);
    // Two zero-value output notes (full withdrawal, no change).
    let (ob0, ob1) = (rand_fr(), rand_fr());
    let oc0 = v3_commit(Fr::from(0u64), note_pubkey, ob0, Fr::from(0u64));
    let oc1 = v3_commit(Fr::from(0u64), note_pubkey, ob1, Fr::from(0u64));

    let ext_amount: i64 = -(amount as i64);
    let ext_data_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(recipient);
        h.update(ext_amount.to_le_bytes());
        h.finalize().into()
    };
    let public_amount = -Fr::from(amount);

    let circuit = TransactCircuitV3 {
        root: Some(fr_to_le(&root)),
        public_amount: Some(fr_to_le(&public_amount)),
        ext_data_hash: Some(ext_data_hash),
        asset_id: Some([0u8; 32]),
        input_nullifiers: vec![Some(fr_to_le(&nf0)), Some(fr_to_le(&nf1))],
        output_commitments: vec![Some(fr_to_le(&oc0)), Some(fr_to_le(&oc1))],
        in_amounts: vec![Some(amount), Some(0)],
        in_privkeys: vec![Some(fr_to_le(&sk)), Some(fr_to_le(&dsk))],
        in_blindings: vec![Some(fr_to_le(&blinding)), Some(fr_to_le(&dbl))],
        in_leaf_indices: vec![Some(leaf_index), Some(0)],
        in_paths: vec![Some(membership.path.clone()), Some(membership.path.clone())],
        out_amounts: vec![Some(0), Some(0)],
        out_pubkeys: vec![Some(fr_to_le(&note_pubkey)), Some(fr_to_le(&note_pubkey))],
        out_blindings: vec![Some(fr_to_le(&ob0)), Some(fr_to_le(&ob1))],
    };

    let proof = Groth16ProofSystem::prove(proving_key, circuit, &mut ark_std::rand::thread_rng())
        .map_err(|e| TransactSubmitError::Prove(e.to_string()))?;
    let mut body = Vec::new();
    proof
        .serialize_compressed(&mut body)
        .map_err(|e| TransactSubmitError::Prove(e.to_string()))?;
    let proof = tag_proof(ProofSuite::Groth16Bn254TransactV3, &body);

    // Self-verify against the node's verifying key *before* returning, so a
    // proving/verifying-key mismatch (e.g. a stale dev proving key against the
    // ceremony VK) or a witness bug fails here — locally, for free — instead of
    // after the deposit is spent and the withdraw silently times out at the
    // quorum. This reproduces the node's `verify_transact_parts` exactly (same
    // VK path, same public-input derivation from `recipient`/`ext_amount`).
    let verdict = ProofVerifier::verify_transact_parts(
        &membership.root,
        recipient,
        ext_amount,
        &[0u8; 32],
        &[fr_to_le(&nf0), fr_to_le(&nf1)],
        &[fr_to_le(&oc0), fr_to_le(&oc1)],
        &proof,
    );
    if !verdict.is_valid() {
        return Err(TransactSubmitError::SelfVerify(format!("{verdict:?}")));
    }

    Ok(WithdrawToFresh {
        proof,
        nullifiers: [fr_to_le(&nf0), fr_to_le(&nf1)],
        output_commitments: [fr_to_le(&oc0), fr_to_le(&oc1)],
        root: membership.root,
        ext_amount,
    })
}

/// POST a withdraw-to-fresh transact to the public ingress. `ciphertexts` must
/// be exactly two well-formed `EncryptedNote` envelopes. Returns the ingress
/// `request_id`.
#[allow(clippy::too_many_arguments)]
pub fn post_transact(
    ingress: &str,
    recipient: &[u8; 32],
    w: &WithdrawToFresh,
    ciphertexts: [Vec<u8>; 2],
) -> Result<String> {
    let body = serde_json::json!({
        "recipient": hex::encode(recipient),
        "nullifiers": [hex::encode(w.nullifiers[0]), hex::encode(w.nullifiers[1])],
        "output_commitments": [
            hex::encode(w.output_commitments[0]),
            hex::encode(w.output_commitments[1]),
        ],
        "root": hex::encode(w.root),
        "ext_amount": w.ext_amount,
        "proof": hex::encode(&w.proof),
        "ciphertexts": [hex::encode(&ciphertexts[0]), hex::encode(&ciphertexts[1])],
    });
    let resp = reqwest::blocking::Client::new()
        .post(format!("{ingress}/transact/submit"))
        .json(&body)
        .send()
        .map_err(|e| TransactSubmitError::Http(e.to_string()))?;
    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| TransactSubmitError::Http(e.to_string()))?;
    if !status.is_success() {
        return Err(TransactSubmitError::IngressRejected {
            status: status.as_u16(),
            body: text,
        });
    }
    Ok(text)
}

/// Poll on-chain until the quorum settles the withdraw: `recipient` funded and
/// the `nf0` nullifier PDA recorded. Returns the recipient's realized balance
/// (lamports actually received, i.e. `amount - fee`).
pub fn wait_for_settlement(
    client: &RpcClient,
    program_id: &Pubkey,
    recipient: &Pubkey,
    nf0: &[u8; 32],
    timeout: Duration,
) -> Result<u64> {
    let (nf_pda, _) = derive_nullifier_account(program_id, nf0);
    let deadline = std::time::Instant::now() + timeout;
    let step = Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(step);
        let bal = client.get_balance(recipient).unwrap_or(0);
        if bal > 0 && client.get_account(&nf_pda).is_ok() {
            return Ok(bal);
        }
    }
    Err(TransactSubmitError::SettlementTimeout(timeout))
}

/// Whether the transact ingress has a validator quorum available (the registry
/// has >= 2 active validators). Cheap pre-check before proving so we fail fast
/// with a clear reason rather than after a 60s+ settlement wait.
pub fn quorum_available(client: &RpcClient, program_id: &Pubkey) -> bool {
    let (registry, _) = derive_validator_registry(program_id);
    match client.get_account_data(&registry) {
        // active_validators is the u64 at [48..56] after the 8-byte discriminator.
        Ok(d) if d.len() >= 56 => u64::from_le_bytes(d[48..56].try_into().unwrap_or([0; 8])) >= 2,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a serialized on-chain `merkle_tree` account image after appending
    /// `leaves` in order, mirroring `programs/paraloom/src/merkle_tree.rs`.
    fn simulated_tree_account(leaves: &[Fr]) -> Vec<u8> {
        let mut zeros = vec![Fr::from(0u64)];
        for k in 0..TX_LEVELS {
            zeros.push(v3_merkle_pair(zeros[k], zeros[k]));
        }
        let mut filled: Vec<Fr> = zeros[..TX_LEVELS].to_vec();
        let mut root = zeros[TX_LEVELS];
        for (next_index, &leaf) in leaves.iter().enumerate() {
            let mut cur = leaf;
            let mut idx = next_index;
            for level in 0..TX_LEVELS {
                if idx & 1 == 0 {
                    filled[level] = cur;
                    cur = v3_merkle_pair(cur, zeros[level]);
                } else {
                    cur = v3_merkle_pair(filled[level], cur);
                }
                idx >>= 1;
            }
            root = cur;
        }

        let mut raw = vec![0u8; 56 + TX_LEVELS * 32];
        raw[8..16].copy_from_slice(&(leaves.len() as u64).to_le_bytes());
        raw[24..56].copy_from_slice(&fr_to_le(&root));
        for (level, f) in filled.iter().enumerate() {
            let off = 56 + level * 32;
            raw[off..off + 32].copy_from_slice(&fr_to_le(f));
        }
        raw
    }

    fn fold_membership_root(commitment: Fr, m: &Membership) -> [u8; 32] {
        let mut cur = commitment;
        for (level, sib) in m.path.iter().enumerate() {
            let s = Fr::from_le_bytes_mod_order(sib);
            cur = if (m.leaf_index >> level) & 1 == 1 {
                v3_merkle_pair(s, cur)
            } else {
                v3_merkle_pair(cur, s)
            };
        }
        fr_to_le(&cur)
    }

    #[test]
    fn membership_from_leaves_reconstructs_paths_for_non_latest_leaves() {
        let c0 = v3_commit(Fr::from(1_000u64), Fr::from(11u64), Fr::from(21u64), Fr::from(0u64));
        let c1 = v3_commit(Fr::from(2_000u64), Fr::from(12u64), Fr::from(22u64), Fr::from(0u64));
        let c2 = v3_commit(Fr::from(3_000u64), Fr::from(13u64), Fr::from(23u64), Fr::from(0u64));

        let raw = simulated_tree_account(&[c0, c1, c2]);
        let root_onchain: [u8; 32] = raw[24..56].try_into().unwrap();
        let leaves = vec![fr_to_le(&c0), fr_to_le(&c1), fr_to_le(&c2)];

        // Only the very last appended leaf (index 2) succeeds via the
        // `filled_subtrees` + `zeros` fast path; earlier leaves (0 and 1) fail
        // with `RootMismatch` because subsequent leaves altered their right
        // siblings and overwrote `filled_subtrees`.
        assert!(matches!(
            membership_from_tree_account(&raw, 0, c0),
            Err(TransactSubmitError::RootMismatch { leaf_index: 0 })
        ));
        assert!(matches!(
            membership_from_tree_account(&raw, 1, c1),
            Err(TransactSubmitError::RootMismatch { leaf_index: 1 })
        ));
        let m2_fast = membership_from_tree_account(&raw, 2, c2).expect("latest leaf fast path");
        assert_eq!(fold_membership_root(c2, &m2_fast), root_onchain);

        // `membership_from_leaves` reconstructs valid paths folding to
        // `root_onchain` for EVERY leaf (0, 1, and 2).
        for (idx, c) in [(0u64, c0), (1u64, c1), (2u64, c2)] {
            let m = membership_from_leaves(&leaves, idx, c, &root_onchain)
                .expect("membership_from_leaves must succeed for any leaf < next_index");
            assert_eq!(m.root, root_onchain);
            assert_eq!(fold_membership_root(c, &m), root_onchain);
        }
    }

    #[test]
    fn parse_leaves_from_tx_logs_rebuilds_deposits_and_transacts_and_ignores_foreign_cpi() {
        let prog = "8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP";
        let foreign = "Foreign111111111111111111111111111111111111";

        let c0 = [0x11u8; 32];
        let c1 = [0x22u8; 32];
        let c2 = [0x33u8; 32];
        let c3 = [0x44u8; 32];

        // DepositNoteEvent at index 0
        let mut dep0 = Vec::with_capacity(8 + 80);
        dep0.extend_from_slice(&DEPOSIT_NOTE_EVENT_DISCRIMINATOR);
        dep0.extend_from_slice(&[0u8; 32]); // depositor
        dep0.extend_from_slice(&100u64.to_le_bytes()); // amount
        dep0.extend_from_slice(&c0); // commitment @ 40..72
        dep0.extend_from_slice(&0u64.to_le_bytes()); // leaf_index @ 72..80
        dep0.extend_from_slice(&0i64.to_le_bytes()); // timestamp

        // DepositNoteSplEvent at index 1
        let mut dep1 = Vec::with_capacity(8 + 112);
        dep1.extend_from_slice(&DEPOSIT_NOTE_SPL_EVENT_DISCRIMINATOR);
        dep1.extend_from_slice(&[0u8; 32]); // depositor
        dep1.extend_from_slice(&[1u8; 32]); // mint
        dep1.extend_from_slice(&200u64.to_le_bytes()); // amount
        dep1.extend_from_slice(&c1); // commitment @ 72..104
        dep1.extend_from_slice(&1u64.to_le_bytes()); // leaf_index @ 104..112
        dep1.extend_from_slice(&0i64.to_le_bytes()); // timestamp

        // TransactEvent appending c2, c3 at indices 2, 3
        let mut tx_ev = Vec::with_capacity(8 + 168);
        tx_ev.extend_from_slice(&TRANSACT_EVENT_DISCRIMINATOR);
        tx_ev.extend_from_slice(&[0xaa; 32]); // nf0
        tx_ev.extend_from_slice(&[0xbb; 32]); // nf1
        tx_ev.extend_from_slice(&c2); // oc0 @ 64..96
        tx_ev.extend_from_slice(&c3); // oc1 @ 96..128
        tx_ev.extend_from_slice(&[0u8; 32]); // new_root

        let logs_tx0 = vec![
            format!("Program {prog} invoke [1]"),
            format!(
                "Program data: {}",
                base64::engine::general_purpose::STANDARD.encode(&dep0)
            ),
            format!("Program {foreign} invoke [2]"),
            format!(
                "Program data: {}",
                base64::engine::general_purpose::STANDARD.encode(&dep0)
            ),
            format!("Program {foreign} success"),
            format!("Program {prog} success"),
        ];
        let logs_tx1 = vec![
            format!("Program {prog} invoke [1]"),
            format!(
                "Program data: {}",
                base64::engine::general_purpose::STANDARD.encode(&dep1)
            ),
            format!(
                "Program data: {}",
                base64::engine::general_purpose::STANDARD.encode(&tx_ev)
            ),
            format!("Program {prog} success"),
        ];

        let parsed = parse_leaves_from_tx_logs(&[logs_tx0, logs_tx1], prog);
        assert_eq!(parsed, vec![(0, c0), (1, c1), (2, c2), (3, c3)]);
    }
}
