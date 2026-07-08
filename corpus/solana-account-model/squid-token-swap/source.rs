use anchor_lang::prelude::*;

declare_id!("SSwpkEEcbUqx4vtoEUTx386698QHNck6A3kCz9Qp4bF");

#[program]
pub mod squid_swap {
    use super::*;

    pub fn withdraw_tokens(ctx: Context<WithdrawTokens>, amount: u64) -> Result<()> {
        // BUG: no owner check on destination - anyone can withdraw to arbitrary address
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
    /// BUG: destination is unchecked - no has_one or constraint
    pub destination: AccountInfo<'info>,
}
