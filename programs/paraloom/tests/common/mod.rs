//! Shared test harness for programs/paraloom integration tests.
//!
//! Houses the Anchor-entry-to-`processor!` adapter that every test
//! file would otherwise inline a copy of. The transmute is sound
//! because `solana-program-test`'s accounts slice owns its element
//! borrows for at least as long as the call — a property the
//! correlated-lifetime signature on Anchor 0.31's generated `entry`
//! requires but `processor!`'s decoupled fn-pointer signature does
//! not let the type system express directly.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::entrypoint::ProgramResult;

#[allow(clippy::missing_safety_doc)]
pub fn entry<'a, 'b, 'c, 'd>(
    program_id: &'a Pubkey,
    accounts: &'b [AccountInfo<'c>],
    data: &'d [u8],
) -> ProgramResult {
    paraloom_program::entry(
        program_id,
        unsafe { std::mem::transmute::<&'b [AccountInfo<'c>], &'b [AccountInfo<'b>]>(accounts) },
        data,
    )
}
