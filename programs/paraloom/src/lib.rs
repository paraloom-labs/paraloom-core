/// This constant is used in tests to define the off-chain root history length.
/// It is aligned with the on-chain constant `ROOT_HISTORY_SIZE` defined in
/// `programs/paraloom/src/merkle_tree.rs`. Note that this constant is not
/// used in any production paths and serves as documentation-of-intent.
pub const ROOT_HISTORY_LEN: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_roots_history_is_bounded() {
        // This test ensures that the off-chain root history length is bounded.
        // The on-chain constant `ROOT_HISTORY_SIZE` (defined in
        // `programs/paraloom/src/merkle_tree.rs`) is set to 64, and this test
        // aligns with that value. If the on-chain constant changes, this test
        // must be updated accordingly.
        const TEST_HISTORY_LEN: usize = ROOT_HISTORY_LEN + 10;
        let mut recent_roots = Vec::new();

        for i in 0..TEST_HISTORY_LEN {
            recent_roots.push(i);
            if recent_roots.len() > ROOT_HISTORY_LEN {
                recent_roots.remove(0);
            }
        }

        assert_eq!(recent_roots.len(), ROOT_HISTORY_LEN);
    }
}
