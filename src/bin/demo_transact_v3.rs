//! Live v3 end-to-end driver (#350): deposit_note on devnet → prove the
//! unified transact with the persistent dev keys → POST to the public
//! transact ingress → watch the 2-of-2 validator quorum settle it on-chain.
//!
//! ```sh
//! SOLANA_RPC_URL=https://api.devnet.solana.com \
//! SOLANA_PROGRAM_ID=8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP \
//! BRIDGE_AUTHORITY_KEYPAIR_PATH=~/.config/solana/paraloom-devnet.json \
//! TRANSACT_INGRESS_URL=https://node.paraloom.io \
//! cargo run --release --bin demo-transact-v3
//! ```

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use paraloom::bridge::solana::*;
use paraloom::privacy::circuits::{Groth16ProofSystem, TransactCircuitV3, TX_LEVELS};
use paraloom::privacy::poseidon_circom::{
    v3_commit, v3_merkle_pair, v3_nullifier, v3_pubkey, v3_signature,
};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let program_id = Pubkey::from_str(&std::env::var("SOLANA_PROGRAM_ID")?)?;
    let payer = load_keypair_from_file(&std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?)?;
    let ingress = std::env::var("TRANSACT_INGRESS_URL")
        .unwrap_or_else(|_| "https://node.paraloom.io".to_string());

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
    let (vault_pda, _) = derive_bridge_vault(&program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);

    // ── 1. deposit_note: 0.1 SOL as a fresh v3 note ─────────────────────────
    const AMOUNT: u64 = 100_000_000; // 0.1 SOL
    let sk = rand_fr();
    let blinding = rand_fr();
    let pk_note = v3_pubkey(sk);
    println!("[1/5] deposit_note: 0.1 SOL...");
    let ix = create_deposit_note_instruction(
        &program_id,
        &payer.pubkey(),
        &vault_pda,
        AMOUNT,
        fr_to_le(&pk_note),
        fr_to_le(&blinding),
    )?;
    let bh = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], bh);
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("      deposit sig: {sig}");

    // ── 2. read the tree: our leaf index + the post-deposit root ────────────
    let raw = client.get_account_data(&tree_pda)?;
    let next_index = u64::from_le_bytes(raw[8..16].try_into()?);
    let leaf_index = next_index - 1;
    let root_onchain: [u8; 32] = raw[24..56].try_into()?;
    println!(
        "[2/5] on-chain tree: leaf {leaf_index}, root {}",
        hex::encode(root_onchain)
    );

    // Authentication path of the just-appended leaf, derived purely from the
    // on-chain `filled_subtrees` + the zero-subtree hashes — a standard
    // incremental-tree property: at each level the sibling is the stored left
    // (`filled_subtrees[level]`) when our index bit is 1, else the zero hash.
    // No other leaves or event scanning needed, and it folds to exactly the
    // on-chain root.
    let commitment = v3_commit(Fr::from(AMOUNT), pk_note, blinding, Fr::from(0u64));
    let mut zeros = vec![Fr::from(0u64)];
    for k in 0..TX_LEVELS {
        zeros.push(v3_merkle_pair(zeros[k], zeros[k]));
    }
    // filled_subtrees[32][32] starts at offset disc(8)+next_index(8)+root_index(8)+root(32)=56.
    let mut path: Vec<[u8; 32]> = Vec::with_capacity(TX_LEVELS);
    #[allow(clippy::needless_range_loop)]
    for level in 0..TX_LEVELS {
        let sib = if (leaf_index >> level) & 1 == 1 {
            let off = 56 + level * 32;
            let fs: [u8; 32] = raw[off..off + 32].try_into()?;
            fs
        } else {
            fr_to_le(&zeros[level])
        };
        path.push(sib);
    }
    // Fold to verify our local path matches the on-chain root before proving.
    let mut cur = commitment;
    for (level, sib) in path.iter().enumerate() {
        let s = Fr::from_le_bytes_mod_order(sib);
        cur = if (leaf_index >> level) & 1 == 1 {
            v3_merkle_pair(s, cur)
        } else {
            v3_merkle_pair(cur, s)
        };
    }
    assert_eq!(
        fr_to_le(&cur),
        root_onchain,
        "membership path must fold to the on-chain root"
    );
    println!("      membership path folds to the on-chain root ✓");
    let root = Fr::from_le_bytes_mod_order(&root_onchain);

    // ── 3. prove the transact: withdraw the full note to a fresh recipient ──
    println!("[3/5] proving (TransactCircuitV3, persistent dev keys)...");
    let recipient = solana_sdk::signature::Keypair::new();
    let recipient_bytes = recipient.pubkey().to_bytes();
    let ext_amount: i64 = -(AMOUNT as i64);

    let sig0 = v3_signature(sk, commitment, Fr::from(leaf_index));
    let nf0 = v3_nullifier(commitment, Fr::from(leaf_index), sig0);
    // Dummy second input (zero value, membership skipped in-circuit).
    let dsk = rand_fr();
    let dbl = rand_fr();
    let dc = v3_commit(Fr::from(0u64), v3_pubkey(dsk), dbl, Fr::from(0u64));
    let dsig = v3_signature(dsk, dc, Fr::from(0u64));
    let nf1 = v3_nullifier(dc, Fr::from(0u64), dsig);
    // Outputs: two zero notes (full withdrawal, no change).
    let (ob0, ob1) = (rand_fr(), rand_fr());
    let oc0 = v3_commit(Fr::from(0u64), pk_note, ob0, Fr::from(0u64));
    let oc1 = v3_commit(Fr::from(0u64), pk_note, ob1, Fr::from(0u64));

    let ext_data_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(recipient_bytes);
        h.update(ext_amount.to_le_bytes());
        h.finalize().into()
    };
    let public_amount = -Fr::from(AMOUNT);

    let circuit = TransactCircuitV3 {
        root: Some(fr_to_le(&root)),
        public_amount: Some(fr_to_le(&public_amount)),
        ext_data_hash: Some(ext_data_hash),
        asset_id: Some([0u8; 32]),
        input_nullifiers: vec![Some(fr_to_le(&nf0)), Some(fr_to_le(&nf1))],
        output_commitments: vec![Some(fr_to_le(&oc0)), Some(fr_to_le(&oc1))],
        in_amounts: vec![Some(AMOUNT), Some(0)],
        in_privkeys: vec![Some(fr_to_le(&sk)), Some(fr_to_le(&dsk))],
        in_blindings: vec![Some(fr_to_le(&blinding)), Some(fr_to_le(&dbl))],
        in_leaf_indices: vec![Some(leaf_index), Some(0)],
        in_paths: vec![Some(path.clone()), Some(path)],
        out_amounts: vec![Some(0), Some(0)],
        out_pubkeys: vec![Some(fr_to_le(&pk_note)), Some(fr_to_le(&pk_note))],
        out_blindings: vec![Some(fr_to_le(&ob0)), Some(fr_to_le(&ob1))],
    };

    let pk_bytes = std::fs::read("keys/transact_v3_proving.key")?;
    let proving_key =
        ark_groth16::ProvingKey::<ark_bn254::Bn254>::deserialize_compressed(&pk_bytes[..])?;
    let proof = Groth16ProofSystem::prove(&proving_key, circuit, &mut ark_std::rand::thread_rng())?;
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;
    println!("      proof ready ({} bytes compressed)", proof_bytes.len());

    // Reproduce the NODE's verification exactly: derive public_amount +
    // ext_data_hash from ext_amount/recipient the same way verify_transact_parts
    // does, and verify against the persistent vk. If this fails locally, the
    // node will too — and we see it before the 120s network wait.
    {
        use paraloom::privacy::ProofVerifier;
        // Verify against the SAME public inputs the circuit was given (proof
        // side), lifting each 32-byte blob mod p — this must pass.
        let vk_bytes = std::fs::read("keys/transact_v3_verifying.key")?;
        let vk =
            ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(&vk_bytes[..])?;
        let proof_side = vec![
            Fr::from_le_bytes_mod_order(&fr_to_le(&root)),
            Fr::from_le_bytes_mod_order(&fr_to_le(&public_amount)),
            Fr::from_le_bytes_mod_order(&ext_data_hash),
            Fr::from_le_bytes_mod_order(&[0u8; 32]),
            Fr::from_le_bytes_mod_order(&fr_to_le(&nf0)),
            Fr::from_le_bytes_mod_order(&fr_to_le(&nf1)),
            Fr::from_le_bytes_mod_order(&fr_to_le(&oc0)),
            Fr::from_le_bytes_mod_order(&fr_to_le(&oc1)),
        ];
        let ok_proof_side = ark_groth16::Groth16::<ark_bn254::Bn254>::verify_proof(
            &ark_groth16::prepare_verifying_key(&vk),
            &proof,
            &proof_side,
        )?;
        println!("      proof-side verify (circuit inputs): {ok_proof_side}");
        let r = ProofVerifier::verify_transact_parts(
            &fr_to_le(&root),
            &recipient_bytes,
            ext_amount,
            &[0u8; 32],
            &[fr_to_le(&nf0), fr_to_le(&nf1)],
            &[fr_to_le(&oc0), fr_to_le(&oc1)],
            &proof_bytes,
        );
        println!("      node-path verify: {r:?}");
        // Where do they differ? public_amount is the prime suspect.
        let node_pa = -Fr::from(ext_amount.unsigned_abs());
        println!(
            "      public_amount circuit={} node={} eq={}",
            hex::encode(fr_to_le(&public_amount)),
            hex::encode(fr_to_le(&node_pa)),
            public_amount == node_pa
        );
    }

    // ── 4. POST to the public transact ingress ──────────────────────────────
    println!("[4/5] POST {ingress}/transact/submit ...");
    let body = serde_json::json!({
        "recipient": hex::encode(recipient_bytes),
        "nullifiers": [hex::encode(fr_to_le(&nf0)), hex::encode(fr_to_le(&nf1))],
        "output_commitments": [hex::encode(fr_to_le(&oc0)), hex::encode(fr_to_le(&oc1))],
        "root": hex::encode(fr_to_le(&root)),
        "ext_amount": ext_amount,
        "proof": hex::encode(&proof_bytes),
        "ciphertexts": ["00", "00"],
    });
    let resp = reqwest::blocking::Client::new()
        .post(format!("{ingress}/transact/submit"))
        .json(&body)
        .send()?;
    let status = resp.status();
    let text = resp.text()?;
    println!("      {status}: {text}");
    if !status.is_success() {
        return Err(format!("ingress rejected: {text}").into());
    }

    // ── 5. watch the quorum settle: recipient balance + nullifier PDAs ──────
    println!("[5/5] waiting for the 2-of-2 quorum settlement...");
    let (nf_pda, _) = derive_nullifier_account(&program_id, &fr_to_le(&nf0));
    for i in 0..40 {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let bal = client.get_balance(&recipient.pubkey()).unwrap_or(0);
        if bal > 0 {
            let fee = AMOUNT * 25 / 10_000;
            println!("\n=== SETTLED ===");
            println!(
                "recipient balance: {} lamports (expected {})",
                bal,
                AMOUNT - fee
            );
            let nf_exists = client.get_account(&nf_pda).is_ok();
            println!("nullifier PDA recorded: {nf_exists}");
            let raw = client.get_account_data(&tree_pda)?;
            let ni = u64::from_le_bytes(raw[8..16].try_into()?);
            println!("tree next_index: {ni} (deposit 1 + 2 outputs = 3)");
            println!("\nLIVE v3 TRANSACT SETTLED BY THE VALIDATOR QUORUM ✓");
            return Ok(());
        }
        if i % 5 == 4 {
            println!("      ... still waiting ({}s)", (i + 1) * 3);
        }
    }
    Err("settlement did not land within 120s — check node logs".into())
}
