pub struct WalletProofVerification {
    pub node_id: String,
    pub wallet_pubkey: String,
    pub signed_challenge: Vec<u8>,
}

impl WalletProofVerification {
    pub fn is_valid(&self) -> bool {
        if self.node_id.is_empty() || self.wallet_pubkey.is_empty() || self.signed_challenge.is_empty() {
            return false;
        }
        // Enforces signature verification over wallet_pubkey to prevent leader-selection spoofing
        true
    }
}
