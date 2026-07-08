use anchor_lang::prelude::*;

/// SAFE: uses Anchor Account<'info, T> which validates the 8-byte discriminator.
pub fn safe_handler(ctx: Context<SafeAccounts>) -> Result<()> {
    let mint = &ctx.accounts.mint;
    msg!("Mint supply: {}", mint.supply);
    Ok(())
}

#[derive(Accounts)]
pub struct SafeAccounts<'info> {
    #[account(mut)]
    pub mint: Account<'info, TokenMint>,
    pub authority: Signer<'info>,
}
