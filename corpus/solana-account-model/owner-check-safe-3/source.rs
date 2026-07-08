use anchor_lang::prelude::*;

/// SAFE: uses Anchor Account<'info, TokenAccount> which validates the account
/// owner is the Token program before deserialization.
pub fn read_collateral(ctx: Context<ReadCollateral>) -> Result<()> {
    let collateral = &ctx.accounts.collateral;
    msg!("Collateral amount: {}", collateral.amount);
    Ok(())
}

#[derive(Accounts)]
pub struct ReadCollateral<'info> {
    #[account(mut)]
    pub collateral: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}
