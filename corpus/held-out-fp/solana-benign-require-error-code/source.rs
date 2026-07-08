use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod require_error_code {
    use super::*;

    pub fn get_order_status(ctx: Context<GetOrder>) -> Result<u8> {
        Ok(ctx.accounts.order.status_code)
    }
}

#[derive(Accounts)]
pub struct GetOrder<'info> {
    #[account(has_one = owner)]
    pub order: Account<'info, OrderAccount>,
    pub owner: Signer<'info>,
}

#[account]
pub struct OrderAccount {
    pub owner: Pubkey,
    pub status_code: u8,
}
