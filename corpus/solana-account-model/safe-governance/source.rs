use anchor_lang::prelude::*;

declare_id!("Safe2222222222222222222222222222222222222222");

#[program]
pub mod safe_governance {
    use super::*;

    pub fn propose(ctx: Context<Propose>, description: String) -> Result<()> {
        // SAFE: authority is Signer + PDA seeds validated
        let proposal = &mut ctx.accounts.proposal;
        proposal.proposer = ctx.accounts.authority.key();
        proposal.description = description;
        proposal.votes_for = 0;
        proposal.votes_against = 0;
        proposal.bump = ctx.bumps.proposal;
        Ok(())
    }

    pub fn vote(ctx: Context<Vote>, in_favor: bool) -> Result<()> {
        // SAFE: has_one proposal_authority + signer
        let vote_record = &mut ctx.accounts.vote_record;
        vote_record.voter = ctx.accounts.voter.key();
        vote_record.in_favor = in_favor;
        let proposal = &mut ctx.accounts.proposal;
        if in_favor {
            proposal.votes_for += 1;
        } else {
            proposal.votes_against += 1;
        }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Propose<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 256 + 8 + 8 + 1,
        seeds = [b"proposal", authority.key().as_ref()],
        bump
    )]
    pub proposal: Account<'info, Proposal>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Vote<'info> {
    #[account(mut, has_one = proposal_authority)]
    pub proposal: Account<'info, Proposal>,
    #[account(
        init,
        payer = voter,
        space = 8 + 32 + 1,
        seeds = [b"vote", proposal.key().as_ref(), voter.key().as_ref()],
        bump
    )]
    pub vote_record: Account<'info, VoteRecord>,
    #[account(mut)]
    pub voter: Signer<'info>,
    pub system_program: Program<'info, System>,
}
