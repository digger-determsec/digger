import { PublicKey } from "@solana/web3.js";

// SAFE: ?? with a literal default (0.5), not a source call.
// Must NOT fire SilentFailover after the trigger narrowing.
export async function handleSlippage(ctx: any) {
    const slippage = cfg.slippage ?? 0.5;
    const transferIx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.recipient, ctx.accounts.owner, slippage);
    await sendTransaction(ctx.connection, transferIx);
}
