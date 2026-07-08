use anchor_lang::prelude::*;

#[program]
pub mod unvalidated_cpi_require {
    use super::*;

    pub fn relay_transfer(ctx: Context<RelayTransfer>, amount: u64) -> Result<()> {
        // SAFE: has require! macro that validates amount, plus signer constraint.
        // The function has AuthorityCheck operations, so the detector suppresses.
        require!(amount > 0, ErrorCode::ZeroAmount);
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.recipient.to_account_info(),
        };
        token::transfer(cpi_accounts, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct RelayTransfer<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[error_code]
pub enum ErrorCode {
    ZeroAmount,
}
