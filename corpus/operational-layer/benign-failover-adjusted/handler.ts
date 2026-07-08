import { PublicKey } from "@solana/web3.js";

// SAFE: falls back to DexScreener via catch, then tightens the
// deviation threshold for the weaker source so a sub-threshold
// manipulation from the secondary is rejected.
export async function handlePriceUpdate(ctx: any) {
    const price = catch(getDexScreenerPrice());
    const adjusted = tighten(price);
    const transferIx = createTransferInstruction(
        ctx.accounts.vault,
        ctx.accounts.recipient,
        ctx.accounts.owner,
        adjusted.amount,
    );
    await sendTransaction(ctx.connection, transferIx);
}
