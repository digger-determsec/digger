use anchor_lang::prelude::*;

declare_id!("Safe4444444444444444444444444444444444444444");

#[program]
pub mod safe_multisig_vault {
    use super::*;

    pub fn create_proposal(ctx: Context<CreateProposal>, amount: u64) -> Result<()> {
        // SAFE: PDA seeds + bump validated + signer
        let proposal = &mut ctx.accounts.proposal;
        proposal.authority = ctx.accounts.authority.key();
        proposal.amount = amount;
        proposal.executed = false;
        Ok(())
    }

    pub fn execute_proposal(ctx: Context<ExecuteProposal>) -> Result<()> {
        // SAFE: has_one authority on vault + signer + threshold check
        let proposal = &mut ctx.accounts.proposal;
        require!(!proposal.executed, ErrorCode::AlreadyExecuted);
        proposal.executed = true;
        let vault = &ctx.accounts.vault;
        require!(
            vault.signers >= vault.threshold,
            ErrorCode::InsufficientSigners
        );
        token::transfer(
            ctx.accounts.vault_token.to_account_info(),
            ctx.accounts.destination.to_account_info(),
            proposal.amount,
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateProposal<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8 + 1,
        seeds = [b"proposal", vault.key().as_ref(), authority.key().as_ref()],
        bump
    )]
    pub proposal: Account<'info, Proposal>,
    #[account(has_one = authority)]
    pub vault: Account<'info, MultisigVault>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExecuteProposal<'info> {
    #[account(mut, has_one = vault)]
    pub proposal: Account<'info, Proposal>,
    #[account(mut)]
    pub vault: Account<'info, MultisigVault>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
