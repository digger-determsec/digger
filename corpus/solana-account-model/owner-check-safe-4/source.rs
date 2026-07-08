use anchor_lang::prelude::*;

/// SAFE: uses Account<'info, TokenAccount> with manual owner check via require!
/// before any data processing.
pub fn read_token_account(ctx: Context<ReadTokenAccount>) -> Result<()> {
    let token_account = &ctx.accounts.token_account;
    require!(
        token_account.owner == &ctx.accounts.expected_owner.key(),
        ErrorCode::UnauthorizedOwner
    );
    msg!("Token amount: {}", token_account.amount);
    Ok(())
}

#[derive(Accounts)]
pub struct ReadTokenAccount<'info> {
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,
    pub expected_owner: Signer<'info>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized owner")]
    UnauthorizedOwner,
}
