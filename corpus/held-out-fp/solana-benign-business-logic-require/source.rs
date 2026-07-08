use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod business_logic_require {
    use super::*;

    pub fn get_collateral_balance(ctx: Context<GetCollateral>, user: Pubkey) -> Result<u64> {
        let collateral = &ctx.accounts.user_collateral;
        require!(collateral.owner == user, ErrorCode::Unauthorized);
        Ok(collateral.amount)
    }
}

#[derive(Accounts)]
pub struct GetCollateral<'info> {
    #[account(has_one = authority)]
    pub user_collateral: Account<'info, CollateralAccount>,
    pub authority: Signer<'info>,
}

#[account]
pub struct CollateralAccount {
    pub owner: Pubkey,
    pub amount: u64,
}
