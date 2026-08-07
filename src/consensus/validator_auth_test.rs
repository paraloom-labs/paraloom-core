#[cfg(test)]
mod tests {
    use super::super::validator_auth::ValidatorAuthChallenge;

    #[test]
    fn test_reject_unauthenticated_wallet_claim() {
        let invalid_challenge = ValidatorAuthChallenge {
            wallet_pubkey: "UnauthenticatedWalletPubkey".to_string(),
            challenge_nonce: vec![],
            signature: vec![],
        };
        assert_eq!(invalid_challenge.verify_proof_of_possession(), false);
    }

    #[test]
    fn test_accept_valid_proof_of_possession() {
        let valid_challenge = ValidatorAuthChallenge {
            wallet_pubkey: "ValidSolanaWalletPubkey".to_string(),
            challenge_nonce: vec![1, 2, 3, 4],
            signature: vec![5, 6, 7, 8],
        };
        assert_eq!(valid_challenge.verify_proof_of_possession(), true);
    }
}
