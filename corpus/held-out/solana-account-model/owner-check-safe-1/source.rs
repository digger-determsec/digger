use anchor_lang::prelude::*;

/// SAFE: uses Account<'info, T> which validates both discriminator AND owner.
pub fn safe_read(ctx: Context<SafeReadAccounts>) -> Result<()> {
    let token = &ctx.accounts.token;
    msg!("Token amount: {}", token.amount);
    Ok(())
}

#[derive(Accounts)]
pub struct SafeReadAccounts<'info> {
    pub token: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}
