use anchor_lang::prelude::*;

#[program]
pub mod solarbridge_cpi {
    use super::*;

    pub fn relay_message(ctx: Context<RelayMessage>, payload: Vec<u8>) -> Result<()> {
        // BUG: CPI call without proper signer validation - privilege escalation
        let cpi_account = &ctx.accounts.target_program;
        let cpi_ctx = CpiContext::new(
            cpi_account.to_account_info(),
            RelayInstruction { payload },
        );
        target_program::cpi::process_relay(cpi_ctx)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct RelayMessage<'info> {
    pub target_program: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
