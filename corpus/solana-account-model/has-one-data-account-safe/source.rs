use anchor_lang::prelude::*;

/// NEGATIVE CONTROL: has_one = mint targets a typed data account (Account<MintData>).
/// This is a completely legitimate Anchor relationship — mint is a data account,
/// never meant to sign. missing_signer must NOT fire here.
#[program]
pub mod has_one_data_account_safe {
    use super::*;

    pub fn process(ctx: Context<ProcessTokens>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.total_deposited += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ProcessTokens<'info> {
    #[account(mut, has_one = mint)]
    pub pool: Account<'info, Pool>,
    /// TYPED data account — legitimate has_one target, never a signer.
    pub mint: Account<'info, MintData>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Pool {
    pub mint: Pubkey,
    pub total_deposited: u64,
}

#[account]
pub struct MintData {
    pub supply: u64,
    pub decimals: u8,
}
