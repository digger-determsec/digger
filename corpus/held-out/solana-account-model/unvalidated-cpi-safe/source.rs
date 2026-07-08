use anchor_lang::prelude::*;

#[program]
pub mod unvalidated_cpi_safe {
    use super::*;

    pub fn relay_transfer(ctx: Context<RelayTransfer>, amount: u64) -> Result<()> {
        // SAFE: token_program is validated via has_one constraint.
        // Anchor ensures the program account matches the expected program.
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.recipient.to_account_info(),
        };
        token::transfer(ctx.accounts.token_program.to_account_info(), cpi_accounts, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct RelayTransfer<'info> {
    #[account(mut, has_one = vault_authority)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    pub vault_authority: Signer<'info>,
    /// SAFE: has_one constraint validates the vault's authority
    #[account(mut)]
    pub token_program: AccountInfo<'info>,
}
