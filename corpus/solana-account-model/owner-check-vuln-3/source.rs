use anchor_lang::prelude::*;

/// BUG: deserializes account data from UncheckedAccount without verifying
/// the account is owned by the expected program. Pattern: lending pool
/// collateral read — attacker passes an account from a different program.
pub fn read_collateral(ctx: Context<ReadCollateral>) -> Result<()> {
    let collateral = &ctx.accounts.collateral;
    let data = collateral.try_borrow_data()?;
    let state: CollateralState = CollateralState::try_from_slice(&data)?;
    // BUG: collateral.owner is never checked against the expected program
    msg!("Collateral amount: {}", state.amount);
    Ok(())
}

#[derive(Accounts)]
pub struct ReadCollateral<'info> {
    #[account(mut)]
    pub collateral: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[derive(BorshDeserialize)]
pub struct CollateralState {
    pub amount: u64,
    pub owner: Pubkey,
}
