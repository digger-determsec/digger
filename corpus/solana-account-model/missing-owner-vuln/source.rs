use anchor_lang::prelude::*;

/// VULN: raw_data is an AccountInfo that receives mutable state writes
/// but has NO owner constraint. Anyone can pass any account here.
/// NOT a has_one target — so missing_signer won't fire, only missing_owner.
#[program]
pub mod missing_owner_vuln {
    use super::*;

    pub fn store_data(ctx: Context<StoreData>, value: u64) -> Result<()> {
        let raw = &ctx.accounts.raw_data;
        // Writes to a raw account — no owner verification
        let data = raw.try_borrow_mut_data()?;
        // Safe to write because the account is mutable (AccountInfo)
        Ok(())
    }
}

#[derive(Accounts)]
pub struct StoreData<'info> {
    /// CHECK: raw account with no owner constraint — ownership confusion
    #[account(mut)]
    pub raw_data: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
