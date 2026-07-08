use anchor_lang::prelude::*;

/// SAFE: uses Anchor Account<'info, T> which validates the 8-byte discriminator.
/// Prevents type confusion attacks.
pub fn deposit_handler(ctx: Context<DepositAccounts>, amount: u64) -> Result<()> {
    let vault_token = &ctx.accounts.vault_token;
    msg!("Vault token amount: {}", vault_token.amount);
    Ok(())
}

#[derive(Accounts)]
pub struct DepositAccounts<'info> {
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}
