//! Shielded transaction types
//!
//! Three main transaction types:
//! 1. Deposit: Public -> Private (mint shielded coins)
//! 2. Transfer: Private -> Private (shielded transfer)
//! 3. Withdraw: Private -> Public (burn shielded coins)

use crate::privacy::types::{Commitment, Note, Nullifier, RangeProof, ShieldedAddress};
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
        let tx_id = uuid::Uuid::new_v4().to_string();
        let output_note = Note::new(recipient, amount - fee, randomness);
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

    /// Range proofs (prove amounts are valid without revealing them)
    pub range_proofs: Vec<RangeProof>,

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

        let range_proofs: Vec<RangeProof> = output_notes
            .iter()
            .map(|_| RangeProof::placeholder())
            .collect();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        TransferTx {
            tx_id,
            input_nullifiers,
            output_commitments,
            output_notes,
            range_proofs,
            zk_proof: Vec::new(), // Placeholder
            merkle_root,
            fee,
            timestamp,
        }
    }

    /// Verify transfer transaction structure
    pub fn verify_structure(&self) -> bool {
        // Must have inputs and outputs
        if self.input_nullifiers.is_empty() || self.output_commitments.is_empty() {
            return false;
        }

        // Outputs and notes must match
        if self.output_commitments.len() != self.output_notes.len() {
            return false;
        }

        // Each commitment must match its note
        for (commitment, note) in self.output_commitments.iter().zip(self.output_notes.iter()) {
            if commitment != &note.commitment() {
                return false;
            }
        }

        // Range proofs must match outputs
        if self.range_proofs.len() != self.output_notes.len() {
            return false;
        }

        true
    }

    /// Verify range proofs
    pub fn verify_range_proofs(&self) -> bool {
        for (proof, commitment) in self.range_proofs.iter().zip(self.output_commitments.iter()) {
            if !proof.verify(commitment) {
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
    pub fn verify(&self) -> bool {
        // Amount must cover fee
        if self.amount < self.fee {
            return false;
        }

        // Must have recipient
        if self.to_public.is_empty() {
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
    pub fn mark_verified(&mut self) {
        self.status = TransactionStatus::Accepted;
        self.confirmations += 1;
    }

    /// Mark as rejected
    pub fn mark_rejected(&mut self, reason: String) {
        self.status = TransactionStatus::Rejected { reason };
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

        let note1 = Note::new(ShieldedAddress([10u8; 32]), 500, [1u8; 32]);
        let note2 = Note::new(ShieldedAddress([20u8; 32]), 490, [2u8; 32]);

        let tx = TransferTx::new(nullifiers, vec![note1, note2], [0u8; 32], 10);

        assert_eq!(tx.input_nullifiers.len(), 2);
        assert_eq!(tx.output_notes.len(), 2);
        assert!(tx.verify_structure());
        assert!(tx.verify_range_proofs());
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
            vec![Note::new(ShieldedAddress([1u8; 32]), 100, [1u8; 32])],
            [0u8; 32],
            10,
        );

        assert!(!tx.verify_structure());
    }
}
