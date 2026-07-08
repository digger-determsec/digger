use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod has_one_guard {
    use super::*;

    pub fn get_config(ctx: Context<GetConfig>) -> Result<u64> {
        Ok(ctx.accounts.config.fee_rate)
    }
}

#[derive(Accounts)]
pub struct GetConfig<'info> {
    #[account(has_one = authority)]
    pub config: Account<'info, ConfigAccount>,
    pub authority: Signer<'info>,
}

#[account]
pub struct ConfigAccount {
    pub authority: Pubkey,
    pub fee_rate: u64,
}
