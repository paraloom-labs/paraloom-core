#[cfg(test)]
mod tests {
    use paraloom_program::merkle_tree::ROOT_HISTORY_SIZE;
    use paraloom_core::privacy::merkle::ROOT_HISTORY_LEN;

    #[test]
    fn offchain_root_history_matches_onchain_ring_buffer() {
        // Both must stay equal or proofs accepted off-chain get rejected on-chain.
        assert_eq!(ROOT_HISTORY_LEN, ROOT_HISTORY_SIZE, "Off-chain root history length must match on-chain ring buffer size");
    }
}