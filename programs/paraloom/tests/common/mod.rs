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
use solana_program_test::ProgramTest;
use solana_sdk::{
    account::Account,
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    signature::{Keypair, Signer},
};

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

/// Derive the BPFLoaderUpgradeable `ProgramData` PDA for a deployed program.
pub fn find_program_data_pda(program_id: Pubkey) -> Pubkey {
    let (pda, _) =
        Pubkey::find_program_address(&[program_id.as_ref()], &bpf_loader_upgradeable::id());
    pda
}

/// Set up the test bank with a fake `ProgramData` account whose
/// `upgrade_authority_address` is a freshly generated, funded keypair.
/// Returns the `ProgramData` PDA and that keypair so tests can use it as the
/// init signer for [`Initialize`] / [`InitializeValidatorRegistry`] (which now
/// require the signer to be the program's upgrade authority — #204).
///
/// Must be called BEFORE `pt.start()` so the account lands in the genesis bank.
pub fn add_program_data(pt: &mut ProgramTest, program_id: Pubkey) -> (Pubkey, Keypair) {
    let upgrade_authority = Keypair::new();
    let program_data_pda = find_program_data_pda(program_id);

    let state = UpgradeableLoaderState::ProgramData {
        slot: 0,
        upgrade_authority_address: Some(upgrade_authority.pubkey()),
    };
    let data = bincode::serialize(&state).expect("serialize ProgramData state");

    pt.add_account(
        program_data_pda,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: bpf_loader_upgradeable::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    // Fund the upgrade authority so it can pay tx fees as the init signer.
    pt.add_account(
        upgrade_authority.pubkey(),
        Account {
            lamports: 100_000_000_000, // 100 SOL — plenty for any test
            data: vec![],
            owner: anchor_lang::solana_program::system_program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    (program_data_pda, upgrade_authority)
}
