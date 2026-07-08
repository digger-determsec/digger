use anchor_lang::prelude::*;

/// SAFE: manual owner check via require_keys_eq!
pub fn safe_manual(ctx: Context<SafeManualAccounts>) -> Result<()> {
    let raw = &ctx.accounts.raw_account;
    require_keys_eq!(
        raw.owner,
        ctx.accounts.expected_program.key(),
        ErrorCode::InvalidOwner
    );
    let data = raw.try_borrow_data()?;
    let state: VaultState = VaultState::try_from_slice(&data)?;
    msg!("Balance: {}", state.balance);
    Ok(())
}

#[derive(Accounts)]
pub struct SafeManualAccounts<'info> {
    pub raw_account: AccountInfo<'info>,
    pub expected_program: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[derive(BorshDeserialize)]
pub struct VaultState {
    pub balance: u64,
}
