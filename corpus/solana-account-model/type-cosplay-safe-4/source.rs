use anchor_lang::prelude::*;

/// SAFE: uses Anchor Account<'info, Mint> which validates the mint structure
/// and discriminator before accepting the account.
pub fn mint_handler(ctx: Context<MintAccounts>, amount: u64) -> Result<()> {
    let mint = &ctx.accounts.mint;
    msg!("Mint supply: {}", mint.supply);
    Ok(())
}

#[derive(Accounts)]
pub struct MintAccounts<'info> {
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    pub authority: Signer<'info>,
}
