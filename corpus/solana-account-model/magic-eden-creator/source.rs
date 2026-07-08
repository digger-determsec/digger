use anchor_lang::prelude::*;

#[program]
pub mod magic_eden_creator {
    use super::*;

    pub fn update_creator(ctx: Context<UpdateCreator>, new_creator: Pubkey) -> Result<()> {
        // BUG: PDA seeds not validated - attacker can provide collision-prone seeds
        let metadata = &mut ctx.accounts.metadata;
        metadata.creator = new_creator;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateCreator<'info> {
    #[account(mut)]
    pub metadata: Account<'info, Metadata>,
    pub payer: Signer<'info>,
}
