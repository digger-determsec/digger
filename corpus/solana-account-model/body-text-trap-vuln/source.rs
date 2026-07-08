use anchor_lang::prelude::*;

/// ADVERSARIAL TRAP: Body contains .owner, require_keys_eq!, and &ctx.accounts.X
/// immutable reference — every string that a body-text suppression gate would
/// match. But the check is WRONG: it compares against the caller's own key
/// (which is always attacker-controlled). The account is genuinely exploitable.
#[program]
pub mod body_text_trap {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &ctx.accounts.vault;
        let authority = &ctx.accounts.authority;

        // TRAP: this check looks like an owner check but compares against
        // authority.key() — which is the Signer, NOT the vault's real owner.
        // The attacker IS the authority, so this check always passes.
        require_keys_eq!(
            vault.owner,
            authority.key(),
            ErrorCode::UnauthorizedOwner
        );

        msg!("Withdraw {} from vault owned by {}", amount, vault.owner);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized owner")]
    UnauthorizedOwner,
}
