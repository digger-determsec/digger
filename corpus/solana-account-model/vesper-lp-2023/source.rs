use anchor_lang::prelude::*;

#[program]
pub mod vesper_lp {
    use super::*;

    pub fn withdraw_tokens(ctx: Context<WithdrawTokens>, amount: u64) -> Result<()> {
        // BUG: no owner check on destination
        let dest = &ctx.accounts.destination;
        let cpi_accounts = Transfer {
            from: ctx.accounts.pool.to_account_info(),
            to: dest.to_account_info(),
        };
        token::transfer(cpi_accounts, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawTokens<'info> {
    #[account(mut)]
    pub pool: Account<'info, TokenAccount>,
    pub destination: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
