use anchor_lang::prelude::*;

#[program]
pub mod raydium_pool {
    use super::*;

    pub fn create_pool(ctx: Context<CreatePool>, fee_bps: u16) -> Result<()> {
        // BUG: PDA bump not validated - attacker can derive collision-prone seeds
        let pool = &mut ctx.accounts.pool;
        pool.fee_bps = fee_bps;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreatePool<'info> {
    #[account(mut, seeds = [b"pool", payer.key().as_ref()], bump)]
    pub pool: Account<'info, PoolState>,
    pub payer: Signer<'info>,
}
