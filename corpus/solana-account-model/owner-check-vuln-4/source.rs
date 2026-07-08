use anchor_lang::prelude::*;

/// BUG: reads metadata from raw AccountInfo without checking account owner.
/// Pattern: metaplex metadata read — attacker substitutes an account owned
/// by a different program that deserializes into the metadata layout.
pub fn read_metadata(ctx: Context<ReadMetadata>) -> Result<()> {
    let metadata_account = &ctx.accounts.metadata_account;
    let data = metadata_account.try_borrow_data()?;
    let metadata: Metadata = Metadata::try_from_slice(&data)?;
    // BUG: metadata_account owner is never checked against the Metaplex program
    msg!("Metadata name: {}", metadata.name);
    Ok(())
}

#[derive(Accounts)]
pub struct ReadMetadata<'info> {
    #[account(mut)]
    pub metadata_account: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[derive(BorshDeserialize)]
pub struct Metadata {
    pub name: String,
    pub symbol: String,
    pub uri: String,
}
