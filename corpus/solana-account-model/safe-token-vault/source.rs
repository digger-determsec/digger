use anchor_lang::prelude::*;

declare_id!("Safe1111111111111111111111111111111111111111");

#[program]
pub mod safe_token_vault {
    use super::*;

    pub fn deposit_tokens(ctx: Context<DepositTokens>, amount: u64) -> Result<()> {
        // SAFE: authority is Signer + has_one constraint
        let vault = &mut ctx.accounts.vault;
        vault.balance += amount;
        token::transfer(
            ctx.accounts.user_token.to_account_info(),
            ctx.accounts.vault_token.to_account_info(),
            amount,
        )?;
        Ok(())
    }

    pub fn withdraw_tokens(ctx: Context<WithdrawTokens>, amount: u64) -> Result<()> {
        // SAFE: owner constraint + PDA with validated seeds + bump
        let vault = &mut ctx.accounts.vault;
        require!(vault.balance >= amount, ErrorCode::InsufficientBalance);
        vault.balance -= amount;
        token::transfer(
            ctx.accounts.vault_token.to_account_info(),
            ctx.accounts.user_token.to_account_info(),
            amount,
        )?;
        Ok(())
    }

    pub fn update_fee(ctx: Context<UpdateFee>, new_fee_bps: u16) -> Result<()> {
        // SAFE: has_one authority + signer check
        let config = &mut ctx.accounts.config;
        require!(new_fee_bps <= 1000, ErrorCode::FeeTooHigh);
        config.fee_bps = new_fee_bps;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct DepositTokens<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawTokens<'info> {
    #[account(mut, seeds = [b"vault", authority.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, VaultState>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateFee<'info> {
    #[account(mut, has_one = admin)]
    pub config: Account<'info, FeeConfig>,
    pub admin: Signer<'info>,
}
