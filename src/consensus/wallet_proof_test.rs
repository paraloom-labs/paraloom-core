#[cfg(test)]
mod tests {
    use super::super::wallet_proof::WalletProofVerification;

    #[test]
    fn test_reject_unverified_wallet_spoofing() {
        let proof = WalletProofVerification {
            node_id: "NodeA".to_string(),
            wallet_pubkey: "SpoofedSolanaWallet".to_string(),
            signed_challenge: vec![],
        };
        assert_eq!(proof.is_valid(), false);
    }

    #[test]
    fn test_accept_verified_wallet_proof() {
        let proof = WalletProofVerification {
            node_id: "NodeA".to_string(),
            wallet_pubkey: "LegitSolanaWallet".to_string(),
            signed_challenge: vec![10, 20, 30, 40],
        };
        assert_eq!(proof.is_valid(), true);
    }
}
