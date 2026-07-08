use anchor_lang::prelude::*;

/// BUG: deserializes account data without verifying the account is owned
/// by the expected program. Uses CPI into an unchecked target.
pub fn process_withdraw(ctx: Context<WithdrawAccounts>, amount: u64) -> Result<()> {
    let target = &ctx.accounts.target_account;
    let data = target.try_borrow_data()?;
    let vault: VaultState = VaultState::try_from_slice(&data)?;
    // BUG: no owner check on target_account — attacker can substitute
    // an account owned by a different program with the same layout
    require!(vault.balance >= amount, ErrorCode::InsufficientBalance);
    Ok(())
}

#[derive(Accounts)]
pub struct WithdrawAccounts<'info> {
    #[account(mut)]
    pub target_account: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[derive(BorshDeserialize)]
pub struct VaultState {
    pub balance: u64,
}
