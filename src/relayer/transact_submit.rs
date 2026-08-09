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
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::time::Duration;

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

/// Read the on-chain merkle tree and reconstruct `leaf_index`'s authentication
/// path from `filled_subtrees` + the zero-subtree hashes — the standard
/// incremental-tree property, no leaf scanning. `commitment` is the leaf value;
/// the path is fold-checked against the on-chain root before returning so a
/// stale/wrong read fails here rather than at proving.
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
