import { PublicKey } from "@solana/web3.js";

// SAFE: bare catch with no source call — error handling, not a data fallback.
// Must NOT fire SilentFailover (narrowed triggers should reject this).
export async function handleErrorLog(ctx: any) {
    try {
        const result = ctx.accounts.data;
        sendTransaction(ctx.connection, result);
    } catch {
        // log error, no source call inside catch
    }
}
