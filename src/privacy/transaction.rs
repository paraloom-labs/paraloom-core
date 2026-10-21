//! Shielded transaction types
//!
//! Three main transaction types:
//! 1. Deposit: Public -> Private (mint shielded coins)
//! 2. Transfer: Private -> Private (shielded transfer)
//! 3. Withdraw: Private -> Public (burn shielded coins)

use crate::privacy::types::{Commitment, Note, Nullifier, ShieldedAddress};
use serde::{Deserialize, Serialize};

/// A shielded transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ShieldedTransaction {
    /// Deposit public funds into shielded pool
    Deposit(DepositTx),

    /// Transfer within shielded pool
    Transfer(TransferTx),

    /// Withdraw from shielded pool to public
    Withdraw(WithdrawTx),
}

impl ShieldedTransaction {
    /// Get transaction ID
    pub fn id(&self) -> String {
        match self {
            ShieldedTransaction::Deposit(tx) => tx.tx_id.clone(),
            ShieldedTransaction::Transfer(tx) => tx.tx_id.clone(),
            ShieldedTransaction::Withdraw(tx) => tx.tx_id.clone(),
        }
    }

    /// Get fee amount
    pub fn fee(&self) -> u64 {
        match self {
            ShieldedTransaction::Deposit(tx) => tx.fee,
            ShieldedTransaction::Transfer(tx) => tx.fee,
            ShieldedTransaction::Withdraw(tx) => tx.fee,
        }
    }
}

/// Deposit transaction: Public -> Private
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositTx {
    /// Transaction ID
    pub tx_id: String,

    /// Public sender address (on Solana/bridge)
    pub from_public: Vec<u8>,

    /// Amount being deposited (in lamports)
    pub amount: u64,

    /// Output commitment (recipient's shielded note)
    pub output_commitment: Commitment,

    /// Output note (encrypted for recipient)
    pub output_note: Note,

    /// Transaction fee
    pub fee: u64,

    /// Timestamp
    pub timestamp: u64,
}

impl DepositTx {
    /// Create a new deposit transaction
    pub fn new(
        from_public: Vec<u8>,
        amount: u64,
        recipient: ShieldedAddress,
        randomness: [u8; 32],
        fee: u64,
    ) -> Self {
        Self::new_asset(
            from_public,
            amount,
            recipient,
            randomness,
            fee,
            crate::privacy::types::NATIVE_SOL_ASSET,
        )
    }

    /// Asset-aware deposit (#237): the output note carries `asset_id` (the
    /// SPL mint's bytes, or `NATIVE_SOL_ASSET` for native SOL), so an SPL
    /// deposit is indexed into the pool under its asset and can later be
    /// withdrawn through `withdraw_spl`.
    pub fn new_asset(
        from_public: Vec<u8>,
        amount: u64,
        recipient: ShieldedAddress,
        randomness: [u8; 32],
        fee: u64,
        asset_id: crate::privacy::types::AssetId,
    ) -> Self {
        let tx_id = uuid::Uuid::new_v4().to_string();
        let output_note = Note::new(recipient, amount - fee, randomness, asset_id);
        let output_commitment = output_note.commitment();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        DepositTx {
            tx_id,
            from_public,
            amount,
            output_commitment,
            output_note,
            fee,
            timestamp,
        }
    }

    /// Verify deposit transaction
    pub fn verify(&self) -> bool {
        // Check amount covers fee
        if self.amount < self.fee {
            return false;
        }

        // Check commitment matches note
        if self.output_commitment != self.output_note.commitment() {
            return false;
        }

        // Check note amount is correct (amount - fee)
        if self.output_note.amount != self.amount - self.fee {
            return false;
        }

        true
    }
}

/// Transfer transaction: Private -> Private
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferTx {
    /// Transaction ID
    pub tx_id: String,

    /// Input nullifiers (spending previous notes)
    pub input_nullifiers: Vec<Nullifier>,

    /// Output commitments (new notes for recipients)
    pub output_commitments: Vec<Commitment>,

    /// Output notes (encrypted for recipients)
    pub output_notes: Vec<Note>,

    /// ZK proof (proves transaction is valid)
    /// Placeholder - will be replaced with actual proof system
    pub zk_proof: Vec<u8>,

    /// Merkle root at time of transaction (anchors the proof)
    pub merkle_root: [u8; 32],

    /// Transaction fee
    pub fee: u64,

    /// Timestamp
    pub timestamp: u64,
}

impl TransferTx {
    /// Create a new transfer transaction
    pub fn new(
        input_nullifiers: Vec<Nullifier>,
        output_notes: Vec<Note>,
        merkle_root: [u8; 32],
        fee: u64,
    ) -> Self {
        let tx_id = uuid::Uuid::new_v4().to_string();

        let output_commitments: Vec<Commitment> =
            output_notes.iter().map(|note| note.commitment()).collect();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        TransferTx {
            tx_id,
            input_nullifiers,
            output_commitments,
            output_notes,
            zk_proof: Vec::new(), // Placeholder
            merkle_root,
            fee,
            timestamp,
        }
    }

    /// Verify transfer transaction structure
    ///
    /// Rejects the shapes that pass a naive "has inputs and outputs" check but
    /// are unsound: a nullifier repeated inside one transaction (the same note
    /// spent twice), an all-zero nullifier, and duplicate output commitments
    /// (which would let one output be counted twice).
    pub fn verify_structure(&self) -> bool {
        // Must have inputs and outputs
        if self.input_nullifiers.is_empty() || self.output_commitments.is_empty() {
            return false;
        }

        // Outputs and notes must match
        if self.output_commitments.len() != self.output_notes.len() {
            return false;
        }

        // Every input nullifier must be non-zero and unique within this
        // transaction. Cross-transaction double-spend is the nullifier set's
        // job, but an intra-transaction duplicate is structurally invalid and
        // must never reach it.
        for (i, nullifier) in self.input_nullifiers.iter().enumerate() {
            if nullifier.0.iter().all(|b| *b == 0) {
                return false;
            }
            if self.input_nullifiers[..i].contains(nullifier) {
                return false;
            }
        }

        // Output commitments must be distinct, so a single output cannot be
        // presented (and later credited) more than once.
        for (i, commitment) in self.output_commitments.iter().enumerate() {
            if self.output_commitments[..i].contains(commitment) {
                return false;
            }
        }

        // Each commitment must match its note
        for (commitment, note) in self.output_commitments.iter().zip(self.output_notes.iter()) {
            if commitment != &note.commitment() {
                return false;
            }
        }

        true
    }
}

/// Withdraw transaction: Private -> Public
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawTx {
    /// Transaction ID
    pub tx_id: String,

    /// Input nullifier (spending shielded note)
    pub input_nullifier: Nullifier,

    /// Amount being withdrawn
    pub amount: u64,

    /// Public recipient address (on Solana)
    pub to_public: Vec<u8>,

    /// ZK proof (proves ownership of nullifier)
    pub zk_proof: Vec<u8>,

    /// Merkle root at time of transaction
    pub merkle_root: [u8; 32],

    /// Transaction fee
    pub fee: u64,

    /// Timestamp
    pub timestamp: u64,
}

impl WithdrawTx {
    /// Create a new withdraw transaction
    pub fn new(
        input_nullifier: Nullifier,
        amount: u64,
        to_public: Vec<u8>,
        merkle_root: [u8; 32],
        fee: u64,
    ) -> Self {
        let tx_id = uuid::Uuid::new_v4().to_string();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        WithdrawTx {
            tx_id,
            input_nullifier,
            amount,
            to_public,
            zk_proof: Vec::new(), // Placeholder
            merkle_root,
            fee,
            timestamp,
        }
    }

    /// Verify withdraw transaction
    ///
    /// Rejects zero-amount withdrawals, withdrawals whose whole amount is
    /// consumed by the fee (no net payout), malformed Solana recipients, and
    /// all-zero input nullifiers.
    pub fn verify(&self) -> bool {
        // Amount must be non-zero and must actually pay something out after
        // the fee; `amount == fee` moves nothing and `amount == 0` is a no-op
        // that would still consume a nullifier.
        if self.amount == 0 || self.amount <= self.fee {
            return false;
        }

        // Recipient must be a full 32-byte Solana public key — not merely
        // non-empty, which would accept a 1-byte address.
        if self.to_public.len() != 32 {
            return false;
        }

        // A zero nullifier is not a valid spend marker and must not be able to
        // enter the nullifier set.
        if self.input_nullifier.0.iter().all(|b| *b == 0) {
            return false;
        }

        true
    }
}

/// Transaction status
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Pending validation
    Pending,

    /// Being verified by validators
    Verifying,

    /// Verified and accepted
    Accepted,

    /// Rejected (invalid)
    Rejected { reason: String },
}

/// Transaction with status
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrackedTransaction {
    /// The transaction
    pub transaction: ShieldedTransaction,

    /// Current status
    pub status: TransactionStatus,

    /// Number of confirmations
    pub confirmations: u32,
}

impl TrackedTransaction {
    /// Create a new tracked transaction
    pub fn new(transaction: ShieldedTransaction) -> Self {
        TrackedTransaction {
            transaction,
            status: TransactionStatus::Pending,
            confirmations: 0,
        }
    }

    /// Mark as verified
    ///
    /// Returns `false` (and leaves the record untouched) if the transaction was
    /// already rejected: a terminal rejection must not be silently upgraded to
    /// `Accepted`. Confirmations saturate rather than overflowing.
    pub fn mark_verified(&mut self) -> bool {
        if matches!(self.status, TransactionStatus::Rejected { .. }) {
            return false;
        }
        self.status = TransactionStatus::Accepted;
        self.confirmations = self.confirmations.saturating_add(1);
        true
    }

    /// Mark as rejected
    ///
    /// Returns `false` (and leaves the record untouched) if the transaction was
    /// already accepted, so an accepted transaction cannot be flipped back to
    /// rejected by a late or duplicated message.
    pub fn mark_rejected(&mut self, reason: String) -> bool {
        if matches!(self.status, TransactionStatus::Accepted) {
            return false;
        }
        self.status = TransactionStatus::Rejected { reason };
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_transaction() {
        let from_public = vec![1u8; 32];
        let recipient = ShieldedAddress([2u8; 32]);
        let randomness = [42u8; 32];

        let tx = DepositTx::new(from_public, 1000, recipient, randomness, 10);

        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.fee, 10);
        assert_eq!(tx.output_note.amount, 990); // 1000 - 10
        assert!(tx.verify());
    }

    #[test]
    fn test_transfer_transaction() {
        let nullifiers = vec![Nullifier([1u8; 32]), Nullifier([2u8; 32])];

        let note1 = Note::new_native(ShieldedAddress([10u8; 32]), 500, [1u8; 32]);
        let note2 = Note::new_native(ShieldedAddress([20u8; 32]), 490, [2u8; 32]);

        let tx = TransferTx::new(nullifiers, vec![note1, note2], [0u8; 32], 10);

        assert_eq!(tx.input_nullifiers.len(), 2);
        assert_eq!(tx.output_notes.len(), 2);
        assert!(tx.verify_structure());
    }

    #[test]
    fn test_withdraw_transaction() {
        let nullifier = Nullifier([1u8; 32]);
        let to_public = vec![5u8; 32];

        let tx = WithdrawTx::new(nullifier, 1000, to_public, [0u8; 32], 10);

        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.fee, 10);
        assert!(tx.verify());
    }

    /// Degenerate withdrawals must not pass structural validation: a zero
    /// amount, an amount entirely eaten by the fee, a short recipient key, or
    /// an all-zero nullifier.
    #[test]
    fn test_withdraw_verify_rejects_degenerate_shapes() {
        let nullifier = Nullifier([1u8; 32]);
        let recipient = vec![5u8; 32];

        // Zero amount.
        assert!(!WithdrawTx::new(nullifier.clone(), 0, recipient.clone(), [0u8; 32], 0).verify());
        // Amount == fee: no net payout.
        assert!(!WithdrawTx::new(nullifier.clone(), 10, recipient.clone(), [0u8; 32], 10).verify());
        // Recipient is not a 32-byte Solana key.
        assert!(!WithdrawTx::new(nullifier.clone(), 100, vec![5u8; 1], [0u8; 32], 1).verify());
        // Zero nullifier would poison the nullifier set.
        assert!(
            !WithdrawTx::new(Nullifier([0u8; 32]), 100, recipient.clone(), [0u8; 32], 1).verify()
        );
        // Well-formed withdrawal still passes.
        assert!(WithdrawTx::new(nullifier, 100, recipient, [0u8; 32], 1).verify());
    }

    /// A terminal rejection must not be silently upgraded, and an accepted
    /// transaction must not be flipped back.
    #[test]
    fn test_tracked_transaction_status_is_monotonic() {
        let tx = ShieldedTransaction::Deposit(DepositTx::new(
            vec![1u8; 32],
            1000,
            ShieldedAddress([2u8; 32]),
            [3u8; 32],
            10,
        ));

        let mut rejected = TrackedTransaction::new(tx.clone());
        assert!(rejected.mark_rejected("bad proof".to_string()));
        assert!(
            !rejected.mark_verified(),
            "rejected must not become accepted"
        );
        assert!(matches!(
            rejected.status,
            TransactionStatus::Rejected { .. }
        ));
        assert_eq!(rejected.confirmations, 0);

        let mut accepted = TrackedTransaction::new(tx);
        assert!(accepted.mark_verified());
        assert_eq!(accepted.confirmations, 1);
        assert!(!accepted.mark_rejected("late".to_string()));
        assert_eq!(accepted.status, TransactionStatus::Accepted);
    }

    #[test]
    fn test_transaction_id() {
        let tx = ShieldedTransaction::Deposit(DepositTx::new(
            vec![1u8; 32],
            1000,
            ShieldedAddress([2u8; 32]),
            [3u8; 32],
            10,
        ));

        let id = tx.id();
        assert!(!id.is_empty());
    }

    #[test]
    fn test_tracked_transaction() {
        let tx = ShieldedTransaction::Deposit(DepositTx::new(
            vec![1u8; 32],
            1000,
            ShieldedAddress([2u8; 32]),
            [3u8; 32],
            10,
        ));

        let mut tracked = TrackedTransaction::new(tx);
        assert_eq!(tracked.status, TransactionStatus::Pending);
        assert_eq!(tracked.confirmations, 0);

        tracked.mark_verified();
        assert_eq!(tracked.status, TransactionStatus::Accepted);
        assert_eq!(tracked.confirmations, 1);
    }

    #[test]
    fn test_invalid_deposit_fee() {
        let mut tx = DepositTx::new(
            vec![1u8; 32],
            1000,
            ShieldedAddress([2u8; 32]),
            [3u8; 32],
            10,
        );

        // Make fee larger than amount
        tx.fee = 2000;
        assert!(!tx.verify());
    }

    #[test]
    fn test_invalid_transfer_structure() {
        let tx = TransferTx::new(
            vec![], // Empty inputs - invalid
            vec![Note::new_native(ShieldedAddress([1u8; 32]), 100, [1u8; 32])],
            [0u8; 32],
            10,
        );

        assert!(!tx.verify_structure());
    }
}
