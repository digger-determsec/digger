use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGSk6idZizNqiAHBysDKg1TkvSaVvWmRGiNbr");

#[program]
pub mod cashio_fixed_mint {
    use super::*;

    pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
        // FIXED: mint authority check via has_one constraint
        let mint = &mut ctx.accounts.mint;
        mint.supply += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct MintTokens<'info> {
    #[account(mut, has_one = mint_authority)]
    pub mint: Account<'info, TokenMint>,
    pub mint_authority: Signer<'info>,
}
