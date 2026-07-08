use anchor_lang::prelude::*;

/// ISOLATION: authority is TYPED (Account<AuthState>), not RAW.
/// fires missing_signer (has_one target without Signer) but NOT missing_owner
/// (which only fires on RAW accounts). Proves the new branch is load-bearing.
#[program]
pub mod missing_signer_typed_vuln {
    use super::*;

    pub fn admin_withdraw(ctx: Context<AdminWithdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance -= amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct AdminWithdraw<'info> {
    #[account(mut, has_one = admin)]
    pub vault: Account<'info, Vault>,
    /// TYPED Account — has_one target, NOT a Signer. Proves missing_signer is load-bearing.
    pub admin: Account<'info, AuthState>,
}

#[account]
pub struct Vault {
    pub admin: Pubkey,
    pub balance: u64,
}

#[account]
pub struct AuthState {
    pub authority: Pubkey,
    pub is_active: bool,
}
