use anchor_lang::prelude::*;

declare_id!("Safe3333333333333333333333333333333333333333");

#[program]
pub mod safe_cpi_proxy {
    use super::*;

    pub fn relay_withdraw(ctx: Context<RelayWithdraw>, amount: u64) -> Result<()> {
        // SAFE: CPI call with proper authority gate - signer + has_one
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token.to_account_info(),
            to: ctx.accounts.recipient.to_account_info(),
        };
        token::transfer(cpi_accounts, amount)?;
        Ok(())
    }

    pub fn update_config(ctx: Context<UpdateConfig>, new_threshold: u64) -> Result<()> {
        // SAFE: PDA with validated seeds + owner check
        let config = &mut ctx.accounts.config;
        config.threshold = new_threshold;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct RelayWithdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    pub recipient: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    #[account(mut, seeds = [b"config", admin.key().as_ref()], bump = config.bump)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}
