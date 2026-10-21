use ark_bn254::Fr;
use paraloom::privacy::commitment::CommitmentGenerator;
use paraloom::privacy::proof_codec::{bytes_to_field, field_to_bytes};
use paraloom::privacy::transaction::{
    ShieldedTransaction, TrackedTransaction, TransactionStatus, TransferTx, WithdrawTx,
};
use paraloom::privacy::types::{Note, Nullifier, ShieldedAddress};

#[test]
fn test_poc_1_commit_note_and_verify_note_opening() {
    let note = Note::new_native(ShieldedAddress([7u8; 32]), 1_000_000, [42u8; 32]);
    let commitment = CommitmentGenerator::commit_note(&note);

    // Verify opening with verify_note_opening works correctly for note commitments
    assert!(
        CommitmentGenerator::verify_note_opening(&commitment, &note),
        "verify_note_opening verifies note commitment correctly"
    );

    let fake_note = Note::new_native(ShieldedAddress([7u8; 32]), 999_999, [42u8; 32]);
    assert!(
        !CommitmentGenerator::verify_note_opening(&commitment, &fake_note),
        "verify_note_opening rejects tampered note"
    );
}

#[test]
fn test_poc_2_proof_codec_trailing_bytes_and_endianness() {
    // 1. field_to_bytes emits big-endian [0, ..., 0, 1] for Fr::from(1u64):
    let one = Fr::from(1u64);
    let bytes = field_to_bytes(&one);
    assert_eq!(bytes[31], 1, "last byte is 1 in big-endian");
    assert_eq!(bytes[0], 0, "first byte is 0 in big-endian");

    // 2. bytes_to_field round-trips correctly:
    let recovered = bytes_to_field(&bytes).expect("round trip");
    assert_eq!(one, recovered);

    // 3. bytes_to_field rejects unconsumed trailing bytes:
    let mut with_trailing = bytes.to_vec();
    with_trailing.extend_from_slice(b"TRAILING_GARBAGE_BYTES");
    assert!(
        bytes_to_field(&with_trailing).is_err(),
        "bytes_to_field rejects trailing unconsumed bytes"
    );
}

#[test]
fn test_poc_3_transaction_validation_and_state_machine_bypasses() {
    // 1. TransferTx::verify_structure rejects duplicate input nullifiers:
    let dup_nf = Nullifier([9u8; 32]);
    let note = Note::new_native(ShieldedAddress([1u8; 32]), 500, [2u8; 32]);
    let transfer_tx = TransferTx::new(vec![dup_nf.clone(), dup_nf], vec![note], [0u8; 32], 10);
    assert!(
        !transfer_tx.verify_structure(),
        "TransferTx::verify_structure must reject duplicate nullifiers"
    );

    // 2. WithdrawTx::verify rejects invalid length recipient, zero net withdrawal, and zero nullifier:
    let withdraw_invalid_recipient =
        WithdrawTx::new(Nullifier([1u8; 32]), 100, vec![0xFF], [0u8; 32], 10);
    assert!(
        !withdraw_invalid_recipient.verify(),
        "WithdrawTx::verify must reject 1-byte recipient"
    );

    let withdraw_zero_net =
        WithdrawTx::new(Nullifier([1u8; 32]), 10, vec![1u8; 32], [0u8; 32], 10);
    assert!(
        !withdraw_zero_net.verify(),
        "WithdrawTx::verify must reject zero net payout"
    );

    let withdraw_zero_nf =
        WithdrawTx::new(Nullifier([0u8; 32]), 100, vec![1u8; 32], [0u8; 32], 10);
    assert!(
        !withdraw_zero_nf.verify(),
        "WithdrawTx::verify must reject zero nullifier"
    );

    // 3. TrackedTransaction::mark_rejected resets confirmations to 0 and mark_verified does not resurrect Rejected:
    let valid_withdraw = WithdrawTx::new(Nullifier([1u8; 32]), 100, vec![1u8; 32], [0u8; 32], 10);
    let mut tracked = TrackedTransaction::new(ShieldedTransaction::Withdraw(valid_withdraw));
    tracked.mark_verified();
    assert_eq!(tracked.confirmations, 1);
    assert_eq!(tracked.status, TransactionStatus::Accepted);

    tracked.mark_rejected("invalid proof".to_string());
    assert_eq!(tracked.confirmations, 0, "Rejected tx resets confirmations to 0");
    assert!(matches!(tracked.status, TransactionStatus::Rejected { .. }));

    tracked.mark_verified();
    assert!(
        matches!(tracked.status, TransactionStatus::Rejected { .. }),
        "Rejected transaction must not be resurrected to Accepted"
    );
}
