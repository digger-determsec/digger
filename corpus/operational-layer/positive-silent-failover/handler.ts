import { PublicKey } from "@solana/web3.js";

// BUG: falls back to DexScreener via catch without tightening the
// deviation threshold — a sub-threshold manipulation that a stronger
// primary source would have caught now passes through.
export async function handlePriceUpdate(ctx: any) {
    const price = catch(getDexScreenerPrice());
    const transferIx = createTransferInstruction(
        ctx.accounts.vault,
        ctx.accounts.recipient,
        ctx.accounts.owner,
        price.amount,
    );
    await sendTransaction(ctx.connection, transferIx);
}
