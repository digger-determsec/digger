use anchor_lang::prelude::*;

/// BUG: reads account data from raw AccountInfo without checking type discriminator.
/// Pattern: SPL token account confusion — attacker passes a different SPL token
/// account type that deserializes into VaultState without validation.
pub fn deposit_handler(ctx: Context<DepositAccounts>, amount: u64) -> Result<()> {
    let vault_account = &ctx.accounts.vault_account;
    let data = vault_account.try_borrow_data()?;
    let vault_state: VaultState = VaultState::try_from_slice(&data)?;
    // BUG: no discriminator check — decoded data is trusted blindly
    msg!("Vault balance: {}", vault_state.balance);
    Ok(())
}

#[derive(Accounts)]
pub struct DepositAccounts<'info> {
    #[account(mut)]
    pub vault_account: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[derive(BorshDeserialize)]
pub struct VaultState {
    pub balance: u64,
    pub owner: Pubkey,
}
