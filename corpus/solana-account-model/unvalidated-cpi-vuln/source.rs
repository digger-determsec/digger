use anchor_lang::prelude::*;

#[program]
pub mod unvalidated_cpi_vuln {
    use super::*;

    pub fn relay_transfer(ctx: Context<RelayTransfer>, amount: u64) -> Result<()> {
        // BUG: CPI target program is not validated against expected program ID.
        // An attacker can substitute a malicious program via the token_program
        // AccountInfo parameter, which has no constraint or has_one binding.
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
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    /// BUG: no constraint, no has_one, no Program<> type validation
    pub token_program: AccountInfo<'info>,
}
