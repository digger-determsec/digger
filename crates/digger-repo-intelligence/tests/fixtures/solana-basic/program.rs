use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod staking_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, rate: u64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.rate = rate;
        Ok(())
    }

    pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
        let user = &mut ctx.accounts.user;
        user.staked += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 8)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut, has_one = authority)]
    pub user: Account<'info, User>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Config {
    pub rate: u64,
}

#[account]
pub struct User {
    pub staked: u64,
}
