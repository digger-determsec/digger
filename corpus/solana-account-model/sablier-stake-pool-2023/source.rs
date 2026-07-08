use anchor_lang::prelude::*;

#[program]
pub mod sablier_stake_pool {
    use super::*;

    pub fn relay_stake(ctx: Context<RelayStake>, amount: u64) -> Result<()> {
        // BUG: CPI call without proper signer validation
        let cpi_accounts = Transfer {
            from: ctx.accounts.stake_token.to_account_info(),
            to: ctx.accounts.recipient.to_account_info(),
        };
        token::transfer(cpi_accounts, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct RelayStake<'info> {
    #[account(mut)]
    pub stake_token: Account<'info, TokenAccount>,
    pub recipient: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
