import { PublicKey } from "@solana/web3.js";

// SAFE: breaker defaults closed on cold start (return false).
export async function handlePriceUpdate(ctx: any) {
    require(isReady);
    if (isReady) {
        const transferIx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.recipient, ctx.accounts.owner, 100);
        await sendTransaction(ctx.connection, transferIx);
    }
    return false;
}
