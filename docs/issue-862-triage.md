# Issue #862 triage — Token-2022 private swaps / re-shields

The bounty text targets `paraloom-wallet` TypeScript files (`src/programs/tokenProgram.ts`,
`src/swap/swapService.ts`, `src/shield/reShield.ts`, `src/shield/unshield.ts`,
`src/constants/programIds.ts`, `lib/paraloom/constants.ts`, `lib/paraloom/privateSwap.ts`,
`lib/paraloom/reshieldRecovery.ts`, `tests/privateSwap.test.ts`, `tests/reShield.test.ts`).

None of those files exist in this repository (`paraloom-core`, a Rust workspace:
`src/bridge/`, `src/privacy/`, `src/relayer/`, `programs/paraloom/`). The wallet is a
separate client crate/repo listed in `docs/bug-bounty.md` scope but not vendored here.

Conclusion: the fix belongs in the `paraloom-wallet` repository. No code change is
applicable in `paraloom-core`; this note records the triage so the issue is not
silently dropped. When fixing it there:

- Define `TOKEN_2022_PROGRAM_ID` (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`) alongside
  the classic SPL constant.
- Resolve the owning token program per mint from the mint account's owner instead of
  hardcoding the classic program, in ATA derivation, account creation, and `depositSpl`.
- Make background re-shield recovery query both classic and Token-2022 ATAs so orphaned
  Token-2022 balances at ephemeral `fresh` addresses are recoverable.
- Add regression tests for the unshield → swap → re-shield round trip with a Token-2022
  output mint and for mixed classic/Token-2022 wallets.
