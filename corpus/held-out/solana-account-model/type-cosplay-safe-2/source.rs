use anchor_lang::prelude::*;

/// SAFE: uses has_one constraint which validates the account type and authority.
pub fn safe_transfer(ctx: Context<SafeTransferAccounts>, amount: u64) -> Result<()> {
    let vault = &ctx.accounts.vault;
    msg!("Vault balance: {}", vault.amount);
    Ok(())
}

#[derive(Accounts)]
pub struct SafeTransferAccounts<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}
