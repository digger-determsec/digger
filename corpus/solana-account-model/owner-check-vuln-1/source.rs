use anchor_lang::prelude::*;

/// BUG: deserializes account data without verifying the account is owned
/// by the expected program. An attacker can pass an account from a different
/// program that deserializes into the same layout.
pub fn drain_handler(ctx: Context<DrainAccounts>) -> Result<()> {
    let vault = &ctx.accounts.vault;
    let data = vault.try_borrow_data()?;
    let state: VaultState = VaultState::try_from_slice(&data)?;
    // BUG: vault.owner is never checked against the expected program
    msg!("Vault owner balance: {}", state.balance);
    Ok(())
}

#[derive(Accounts)]
pub struct DrainAccounts<'info> {
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[derive(BorshDeserialize)]
pub struct VaultState {
    pub balance: u64,
    pub owner: Pubkey,
}
