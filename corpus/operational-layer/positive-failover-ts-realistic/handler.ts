import { PublicKey } from "@solana/web3.js";

// BUG: falls back to cached price on error without tightening deviation threshold.
export async function handleCachedPriceUpdate(ctx: any) {
    const price = catch(getCachedPrice(ctx.accounts.feed));
    const deviation = Math.abs(price - lastPrice);
    const transferIx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.recipient, ctx.accounts.owner, price.amount);
    await sendTransaction(ctx.connection, transferIx);
}
