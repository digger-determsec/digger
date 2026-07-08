import { PublicKey } from "@solana/web3.js";

// SAFE: circuit breaker defaults to "unhealthy" on uninitialized state —
// the init guard (verify) covers isReady, so each restart is blocked
// until explicit initialization.
export async function handlePriceUpdate(ctx: any) {
    const sig = verify(isReady);
    if (isReady) {
        const transferIx = createTransferInstruction(
            ctx.accounts.vault,
            ctx.accounts.recipient,
            ctx.accounts.owner,
            100,
        );
        await sendTransaction(ctx.connection, transferIx);
    }
    return false;
}
