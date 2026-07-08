use anchor_lang::prelude::*;

/// BUG: deserializes data from UncheckedAccount using .try_deserialize() without
/// any Program<> type constraint. Attacker can pass an account from a different
/// program that deserializes into the expected layout.
pub fn mint_handler(ctx: Context<MintAccounts>, amount: u64) -> Result<()> {
    let raw_account = &ctx.accounts.raw_account;
    let account_data = raw_account.try_borrow_data()?;
    let mint_state = MintState::try_deserialize(&mut &account_data[..])?;
    // BUG: no Program<> type guard — raw deserialization trusts any account
    msg!("Mint supply: {}", mint_state.supply);
    Ok(())
}

#[derive(Accounts)]
pub struct MintAccounts<'info> {
    #[account(mut)]
    pub raw_account: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}

#[derive(BorshDeserialize)]
pub struct MintState {
    pub supply: u64,
    pub authority: Pubkey,
}
