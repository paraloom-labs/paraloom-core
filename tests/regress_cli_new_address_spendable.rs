//! Regression test for issue #1653: CLI wallet new-address derives shielded address
//! with Poseidon (v3_pubkey) instead of SHA256, ensuring notes paid to CLI-generated
//! addresses can be spent by the holder of the stored spending key.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use paraloom::privacy::circuits::{TransactCircuitV3, TX_LEVELS};
use paraloom::privacy::poseidon_circom::{
    v3_commit, v3_merkle_pair, v3_nullifier, v3_pubkey, v3_signature,
};
use sha2::{Digest, Sha256};

fn fr_le(f: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = f.into_bigint().to_bytes_le();
    out[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
    out
}

fn zeros() -> Vec<Fr> {
    let mut z = vec![Fr::from(0u64)];
    for k in 0..TX_LEVELS {
        z.push(v3_merkle_pair(z[k], z[k]));
    }
    z
}

fn member_root_and_path(leaf: Fr, index: u64) -> ([u8; 32], Vec<[u8; 32]>) {
    let z = zeros();
    let mut current = leaf;
    for (i, zi) in z.iter().enumerate().take(TX_LEVELS) {
        let bit = (index >> i) & 1;
        current = if bit == 0 {
            v3_merkle_pair(current, *zi)
        } else {
            v3_merkle_pair(*zi, current)
        };
    }
    let path = z[..TX_LEVELS].iter().map(|f| fr_le(*f)).collect();
    (fr_le(current), path)
}

fn synth(c: TransactCircuitV3) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    match c.generate_constraints(cs.clone()) {
        Ok(()) => cs.is_satisfied().expect("cs query"),
        Err(_) => false,
    }
}

fn build_spend(
    note_pubkey: Fr,
    sk: Fr,
    blinding: Fr,
    amount: u64,
    index: u64,
) -> TransactCircuitV3 {
    let asset = Fr::from(0u64); // NATIVE_SOL
    let commitment = v3_commit(Fr::from(amount), note_pubkey, blinding, asset);
    let (root, path) = member_root_and_path(commitment, index);
    let sig = v3_signature(sk, commitment, Fr::from(index));
    let nf = v3_nullifier(commitment, Fr::from(index), sig);

    // Dummy second input
    let dsk = Fr::from(32u64);
    let dbl = Fr::from(4u64);
    let dc = v3_commit(Fr::from(0u64), v3_pubkey(dsk), dbl, asset);
    let dsig = v3_signature(dsk, dc, Fr::from(0u64));
    let dnf = v3_nullifier(dc, Fr::from(0u64), dsig);
    let dummy_path: Vec<[u8; 32]> = zeros()[..TX_LEVELS].iter().map(|f| fr_le(*f)).collect();

    // Outputs
    let out0_pk = v3_pubkey(Fr::from(41u64));
    let out0_bl = Fr::from(7u64);
    let out1_pk = v3_pubkey(Fr::from(42u64));
    let out1_bl = Fr::from(8u64);
    let oc0 = v3_commit(Fr::from(amount), out0_pk, out0_bl, asset);
    let oc1 = v3_commit(Fr::from(0u64), out1_pk, out1_bl, asset);

    TransactCircuitV3 {
        root: Some(root),
        public_amount: Some(fr_le(Fr::from(0u64))),
        ext_data_hash: Some([9u8; 32]),
        asset_id: Some(fr_le(asset)),
        input_nullifiers: vec![Some(fr_le(nf)), Some(fr_le(dnf))],
        output_commitments: vec![Some(fr_le(oc0)), Some(fr_le(oc1))],
        in_amounts: vec![Some(amount), Some(0)],
        in_privkeys: vec![Some(fr_le(sk)), Some(fr_le(dsk))],
        in_blindings: vec![Some(fr_le(blinding)), Some(fr_le(dbl))],
        in_leaf_indices: vec![Some(index), Some(0)],
        in_paths: vec![Some(path), Some(dummy_path)],
        out_amounts: vec![Some(amount), Some(0)],
        out_pubkeys: vec![Some(fr_le(out0_pk)), Some(fr_le(out1_pk))],
        out_blindings: vec![Some(fr_le(out0_bl)), Some(fr_le(out1_bl))],
    }
}

#[test]
fn test_cli_new_address_spendable_regression() {
    // 1. Simulate the keypair generation logic in `wallet new-address`
    let private_key: [u8; 32] = [42u8; 32];

    let fr_to_le = |f: &Fr| -> [u8; 32] {
        let mut out = [0u8; 32];
        let le = f.into_bigint().to_bytes_le();
        out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
        out
    };

    // The fixed CLI derivation using Poseidon v3_pubkey
    let sk_fr = Fr::from_le_bytes_mod_order(&private_key);
    let note_pubkey = v3_pubkey(sk_fr);
    let public_key = fr_to_le(&note_pubkey);
    let address = format!("paraloom1{}", hex::encode(public_key));

    // Also compute what the old buggy derivation (SHA256) would have produced
    let mut hasher = Sha256::new();
    hasher.update(private_key);
    let sha256_public_key: [u8; 32] = hasher.finalize().into();
    let old_buggy_address = format!("paraloom1{}", hex::encode(sha256_public_key));

    // Invariant: fixed public_key is Poseidon, NOT SHA256
    assert_ne!(public_key, sha256_public_key);
    assert_ne!(address, old_buggy_address);

    // 2. Sender deposits / transfers to the new address
    let addr_hex = address.strip_prefix("paraloom1").expect("paraloom1 prefix");
    let addr_bytes_vec = hex::decode(addr_hex).expect("valid hex");
    let mut recipient_bytes = [0u8; 32];
    recipient_bytes.copy_from_slice(&addr_bytes_vec);

    assert_eq!(recipient_bytes, public_key);

    // 3. Sender builds note commitment with recipient_bytes as pubkey
    let amount: u64 = 5000;
    let blinding_fr = Fr::from(17u64);
    let recipient_fr = Fr::from_le_bytes_mod_order(&recipient_bytes);

    // Verify recipient field element matches note_pubkey derived from sk
    assert_eq!(recipient_fr, note_pubkey);

    // 4. Verify functional ZK constraint satisfaction in TransactCircuitV3:
    // A spend witness built from the stored private key for a note paid to the CLI address
    // MUST satisfy the circuit.
    let spend_circuit = build_spend(recipient_fr, sk_fr, blinding_fr, amount, 0);
    assert!(
        synth(spend_circuit),
        "Spend of note paid to fixed CLI address MUST satisfy TransactCircuitV3"
    );

    // 5. Contrast with the old buggy SHA256 address:
    let buggy_recipient_fr = Fr::from_le_bytes_mod_order(&sha256_public_key);
    let buggy_spend_circuit = build_spend(buggy_recipient_fr, sk_fr, blinding_fr, amount, 0);
    assert!(
        !synth(buggy_spend_circuit),
        "Spend of note paid to old SHA256 address must FAIL TransactCircuitV3"
    );
}
