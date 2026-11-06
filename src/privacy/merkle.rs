use paraloom_program::merkle_tree::ROOT_HISTORY_SIZE;

/// The maximum number of historical roots the off-chain client will accept.
/// This must remain synchronized with `paraloom_program::merkle_tree::ROOT_HISTORY_SIZE`
/// to ensure that proofs accepted off-chain are not rejected by the on-chain
/// ring buffer. Shrinking this window tightens the liveness margin; we assume
/// the path server can serve proofs within this 64-slot window.
pub const ROOT_HISTORY_LEN: usize = ROOT_HISTORY_SIZE;