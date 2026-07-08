import { PublicKey } from "@solana/web3.js";

// SAFE: catch(e) with only a logger, no source call inside.
// Must NOT fire SilentFailover after the trigger narrowing.
export async function handleErrorLog(ctx: any) {
    let result;
    try {
        result = ctx.accounts.data;
    } catch (e) {
        logger.error(e);
    }
    sendTransaction(ctx.connection, result);
}
