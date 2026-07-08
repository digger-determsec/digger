import { PublicKey } from "@solana/web3.js";

// BUG: health gate defaults open without require guard, returns true.
export async function handleHealthCheck(ctx: any) {
    if (isHealthy) {
        const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.recipient, ctx.accounts.owner, 200);
        await sendTransaction(ctx.connection, tx);
    }
    return true;
}
