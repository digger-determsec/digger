use anchor_lang::prelude::*;

#[program]
pub mod solend_oracle {
    use super::*;

    pub fn update_oracle_price(ctx: Context<UpdateOracle>, price: u64) -> Result<()> {
        // BUG: no authority check on oracle update - anyone can manipulate price
        let oracle = &mut ctx.accounts.oracle;
        oracle.price = price;
        oracle.last_update = Clock::get()?.unix_timestamp;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateOracle<'info> {
    #[account(mut)]
    pub oracle: Account<'info, OracleState>,
    pub payer: Signer<'info>,
}
