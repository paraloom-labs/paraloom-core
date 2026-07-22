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

use anchor_lang::solana_program::program_option::COption;
use anchor_lang::solana_program::program_pack::Pack;
use solana_sdk::pubkey::Pubkey;

/// Bake an initialized SPL mint into genesis and return its pubkey. Used as the
/// dual-stake `stake_mint` in tests (a stand-in for the real PARALOOM mint).
/// `mint_authority` is arbitrary — tests pre-fund token accounts directly
/// rather than minting through it.
pub fn add_stake_mint(pt: &mut ProgramTest, mint_authority: Pubkey) -> Pubkey {
    let mint = Pubkey::new_unique();
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::Some(mint_authority),
        // Non-zero so a `slash` burn (which reduces supply) never underflows;
        // larger than any amount a test funds into token accounts.
        supply: 1_000_000_000_000_000,
        decimals: 0,
        is_initialized: true,
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    pt.add_account(
        mint,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: spl_token::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    mint
}

/// Bake an initialized SPL token account for `owner` of `mint` holding
/// `amount`, into genesis. Returns its pubkey. Lets a test fund a validator's
/// token balance so `register_validator` can lock the token half.
pub fn add_token_account(pt: &mut ProgramTest, mint: Pubkey, owner: Pubkey, amount: u64) -> Pubkey {
    let token_account = Pubkey::new_unique();
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account {
        mint,
        owner,
        amount,
        delegate: COption::None,
        state: spl_token::state::AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    pt.add_account(
        token_account,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: spl_token::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    token_account
}

/// Derive the shared token-stake vault + its authority PDA for `program_id`.
pub fn stake_vault_pdas(program_id: Pubkey) -> (Pubkey, Pubkey) {
    let (vault, _) = Pubkey::find_program_address(&[b"stake_token_vault"], &program_id);
    let (authority, _) = Pubkey::find_program_address(&[b"stake_vault_authority"], &program_id);
    (vault, authority)
}
