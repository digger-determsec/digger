use anchor_lang::prelude::*;

#[program]
pub mod cpi_oracle_safe_1 {
    use super::*;

    pub fn update_price_feed(ctx: Context<UpdatePriceFeed>, price: u64) -> Result<()> {
        // SAFE: feed account validated via has_one = authority.
        let cpi_accounts = Transfer {
            from: ctx.accounts.fee_vault.to_account_info(),
            to: ctx.accounts.oracle_reward.to_account_info(),
        };
        token::transfer(ctx.accounts.oracle_program.to_account_info(), cpi_accounts, 1000)?;
        msg!("Price updated: {}", price);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdatePriceFeed<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut)]
    pub fee_vault: Account<'info, TokenAccount>,
    #[account(mut, has_one = authority)]
    pub feed: Account<'info, TokenAccount>,
    #[account(mut)]
    pub oracle_reward: AccountInfo<'info>,
    pub oracle_program: AccountInfo<'info>,
}
