use anchor_lang::prelude::*;

#[program]
pub mod cpi_staking_safe_1 {
    use super::*;

    pub fn claim_rewards(ctx: Context<ClaimRewards>, amount: u64) -> Result<()> {
        // SAFE: reward_vault validated via has_one = claimant.
        let cpi_accounts = Transfer {
            from: ctx.accounts.reward_vault.to_account_info(),
            to: ctx.accounts.claimant.to_account_info(),
        };
        token::transfer(ctx.accounts.staking_program.to_account_info(), cpi_accounts, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    #[account(mut)]
    pub claimant: Account<'info, TokenAccount>,
    #[account(mut, has_one = claimant)]
    pub reward_vault: Account<'info, TokenAccount>,
    pub staking_program: AccountInfo<'info>,
}
