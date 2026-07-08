import { PublicKey } from "@solana/web3.js";

// SAFE: fallback source is threshold-adjusted before the sink.
export async function handlePriceUpdate(ctx: any) {
    const price = catch(getDexScreenerPrice());
    const adjusted = tighten(price);
    const transferIx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.recipient, ctx.accounts.owner, adjusted.amount);
    await sendTransaction(ctx.connection, transferIx);
}
