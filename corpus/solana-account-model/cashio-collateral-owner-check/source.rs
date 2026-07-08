use anchor_lang::prelude::*;

/// Minimal repro of Cashio collateral-owner-check missing pattern.
///
/// Based on the public Cashio post-mortem (CertiK, BlockSec, Ackee):
/// The program reads input collateral / Saber swap accounts (AccountInfo)
/// and deserializes them, but never validates that those accounts are
/// owned by the expected program (SPL Token / Saber pool). An attacker
/// can substitute accounts owned by themselves.
///
/// This is the unchecked_account_owner pattern: the program trusts
/// data from an AccountInfo whose owner was never validated.
/// label: reproducer (not the original Cashio source)

declare_id!("Fg6PaFpoGSk6idZizNqiAHBysDKg1TkvSaVvWmRGiNbr");

#[program]
pub mod cashio_repro {
    use super::*;

    /// BUG: reads collateral accounts without owner validation.
    /// The collateral_account could be owned by anyone — the program
    /// never checks that it's owned by the Saber/SPL Token program.
    pub fn mint_with_collateral(
        ctx: Context<MintWithCollateral>,
        amount: u64,
    ) -> Result<()> {
        // BUG: reads data from collateral_account without checking its owner.
        // An attacker can pass an AccountInfo they own, with a fake layout.
        let collateral_data = ctx.accounts.collateral_account.try_borrow_data()?;
        let collateral_state: CollateralState =
            AnchorDeserialize::try_deserialize(&mut &collateral_data[..])?;

        // BUG: trusts collateral_state.value without verifying the account
        // was created/validated by the expected program (SPL Token / Saber).
        require!(collateral_state.value >= amount, ErrorCode::InsufficientCollateral);

        let mint = &mut ctx.accounts.mint;
        mint.supply = mint
            .supply
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct MintWithCollateral<'info> {
    #[account(mut)]
    pub mint: Account<'info, TokenMint>,

    /// BUG: AccountInfo without owner constraint.
    /// The program should validate that this account is owned by
    /// the Saber pool program or SPL Token program.
    /// This is the unchecked_account_owner pattern.
    pub collateral_account: AccountInfo<'info>,

    pub authority: Signer<'info>,
}

#[derive(AnchorDeserialize, AnchorSerialize)]
pub struct CollateralState {
    pub value: u64,
    pub owner: Pubkey,
}
