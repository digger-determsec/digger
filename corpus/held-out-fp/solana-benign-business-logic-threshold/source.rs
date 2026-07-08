use anchor_lang::prelude::*;

/// Business-logic require — NOT an ownership check.
/// require!(amount >= MIN_DEPOSIT) is a numeric threshold, not account validation.
/// This sits on the decision boundary: current detector suppresses via
/// blanket has_require_or_assert, but a tightened detector (per ADR-0035) that
/// distinguishes require-as-ownership from require-as-business-logic would
/// wrongly flag this. The held-out gate catches any such regression.
declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod business_logic_threshold {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        const MIN_DEPOSIT: u64 = 1_000_000;
        require!(amount >= MIN_DEPOSIT, ErrorCode::BelowMinimum);
        ctx.accounts.vault.total_deposited += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub vault: Account<'info, VaultState>,
    pub depositor: Signer<'info>,
}

#[account]
pub struct VaultState {
    pub total_deposited: u64,
}
