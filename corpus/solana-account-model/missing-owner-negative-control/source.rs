use anchor_lang::prelude::*;

/// NEGATIVE CONTROL: has_one = mint targets a typed data account (Account<MintData>).
/// This is a legitimate ownership-shaped pattern — mint has program-ownership
/// validation by construction (Account<T>). No missing_owner findings expected.
#[program]
pub mod missing_owner_negative_control {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.total_deposited += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, has_one = mint)]
    pub pool: Account<'info, Pool>,
    /// SAFE: Account<MintData> verifies program-ownership + discriminator
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
