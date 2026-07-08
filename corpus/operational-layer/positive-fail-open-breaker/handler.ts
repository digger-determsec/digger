import { PublicKey } from "@solana/web3.js";

// BUG: circuit breaker defaults to "healthy" on uninitialized state (isReady
// is false on every cold start), so each restart is a transfer window.
export async function handlePriceUpdate(ctx: any) {
    if (isReady) {
        const transferIx = createTransferInstruction(
            ctx.accounts.vault,
            ctx.accounts.recipient,
            ctx.accounts.owner,
            100,
        );
        await sendTransaction(ctx.connection, transferIx);
    }
    return true;
}
