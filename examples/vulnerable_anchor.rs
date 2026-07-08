// SPDX-License-Identifier: MIT
// Vulnerable Anchor Program — DO NOT DEPLOY
// Intentionally vulnerable for Digger testing

use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod vulnerable_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        Ok(())
    }

    // BUG: No has_one = authority — anyone can deposit
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance += amount;
        Ok(())
    }

    // BUG: No has_one = authority — anyone can withdraw
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        require!(vault.balance >= amount, VaultError::InsufficientBalance);
        vault.balance -= amount;
        Ok(())
    }

    // BUG: CPI without authority validation
    pub fn withdraw_and_transfer(ctx: Context<WithdrawAndTransfer>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        require!(vault.balance >= amount, VaultError::InsufficientBalance);
        vault.balance -= amount;

        // CPI to token program without re-validating authority
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            anchor_spl::token::Transfer {
                from: ctx.accounts.vault_token.to_account_info(),
                to: ctx.accounts.user_token.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
        );
        anchor_spl::token::transfer(cpi_ctx, amount)?;
        Ok(())
    }

    // BUG: Anyone can set authority
    pub fn set_authority(ctx: Context<SetAuthority>, new_authority: Pubkey) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = new_authority;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32 + 8)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]  // BUG: missing has_one = authority
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]  // BUG: missing has_one = authority
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawAndTransfer<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub vault_token: Account<'info, anchor_spl::token::TokenAccount>,
    #[account(mut)]
    pub user_token: Account<'info, anchor_spl::token::TokenAccount>,
    pub token_program: Program<'info, anchor_spl::token::Token>,
}

#[derive(Accounts)]
pub struct SetAuthority<'info> {
    #[account(mut)]  // BUG: missing has_one = authority
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("Insufficient balance")]
    InsufficientBalance,
}
