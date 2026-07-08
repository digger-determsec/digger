use anchor_lang::prelude::*;

#[program]
pub mod steppice_token {
    use super::*;

    pub fn swap_tokens(ctx: Context<SwapTokens>, amount: u64) -> Result<()> {
        // BUG: account type not validated - user passes wrong token account
        let from = &ctx.accounts.from_token;
        let to = &ctx.accounts.to_token;
        // No check that from_token.mint == expected_mint
        token::transfer(from.to_account_info(), to.to_account_info(), amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SwapTokens<'info> {
    #[account(mut)]
    pub from_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to_token: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}
