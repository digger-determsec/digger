use anchor_lang::prelude::*;

#[program]
pub mod cpi_signer_only_vuln {
    use super::*;

    pub fn relay_transfer(ctx: Context<RelayTransfer>, amount: u64) -> Result<()> {
        // VULNERABLE: signer:authority constrains who calls, but NOT which program
        // is invoked. The token_program AccountInfo is unconstrained - attacker
        // can substitute a malicious program.
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
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
