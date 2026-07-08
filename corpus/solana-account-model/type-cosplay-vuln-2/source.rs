use anchor_lang::prelude::*;

/// BUG: reads from UncheckedAccount without discriminator validation.
/// The attacker can pass a fake account that deserializes to arbitrary data.
pub fn process_transfer(ctx: Context<TransferAccounts>, amount: u64) -> Result<()> {
    let pool_account = &ctx.accounts.pool_account;
    let pool_data = pool_account.try_borrow_data()?;
    let pool_state: PoolState = PoolState::try_from_slice(&pool_data)?;
    // BUG: no type discriminator check on pool_account
    require!(pool_state.is_active, ErrorCode::PoolInactive);
    Ok(())
}

#[derive(Accounts)]
pub struct TransferAccounts<'info> {
    #[account(mut)]
    pub pool_account: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[derive(BorshDeserialize)]
pub struct PoolState {
    pub is_active: bool,
    pub total_liquidity: u64,
}
