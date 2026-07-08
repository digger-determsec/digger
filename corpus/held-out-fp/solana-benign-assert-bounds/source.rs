use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod assert_bounds {
    use super::*;

    pub fn get_validator(ctx: Context<GetValidator>, index: u8) -> Result<Pubkey> {
        let validators = &ctx.accounts.state.validators;
        let idx = index as usize;
        require!(idx < validators.len(), ErrorCode::IndexOutOfBounds);
        Ok(validators[idx])
    }
}

#[derive(Accounts)]
pub struct GetValidator<'info> {
    #[account(has_one = authority)]
    pub state: Account<'info, ValidatorState>,
    pub authority: Signer<'info>,
}

#[account]
pub struct ValidatorState {
    pub authority: Pubkey,
    pub validators: Vec<Pubkey>,
}
