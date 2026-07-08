use anchor_lang::prelude::*;

/// BUG: reads account data from raw AccountInfo without checking type discriminator.
/// An attacker can pass an account of a different type and have it accepted.
pub fn relay_handler(ctx: Context<RelayAccounts>, amount: u64) -> Result<()> {
    let source_account = &ctx.accounts.source_account;
    let data = source_account.try_borrow_data()?;
    let decoded: VaultState = VaultState::try_from_slice(&data)?;
    // BUG: no discriminator check, no owner check — decoded data is trusted blindly
    msg!("Balance: {}", decoded.balance);
    Ok(())
}

#[derive(Accounts)]
pub struct RelayAccounts<'info> {
    #[account(mut)]
    pub source_account: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[derive(BorshDeserialize)]
pub struct VaultState {
    pub balance: u64,
    pub owner: Pubkey,
}
