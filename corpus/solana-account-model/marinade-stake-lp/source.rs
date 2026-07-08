use anchor_lang::prelude::*;

#[program]
pub mod marinade_stake_lp {
    use super::*;

    pub fn add_liquidity(ctx: Context<AddLiquidity>, amount: u64) -> Result<()> {
        // BUG: account confusion - from_token and lp_token could be swapped
        let from = &ctx.accounts.from_token;
        let lp = &ctx.accounts.lp_token;
        token::transfer(from.to_account_info(), lp.to_account_info(), amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct AddLiquidity<'info> {
    #[account(mut)]
    pub from_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub lp_token: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}
