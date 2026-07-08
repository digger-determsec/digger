import { PublicKey } from "@solana/web3.js";

// BUG: DB-sourced recipient used in transfer without allowlist check.
export async function handleDBRoute(ctx: any) {
    const recipient = db.get("recipient");
    const tx = createTransferInstruction(ctx.accounts.vault, recipient, ctx.accounts.owner, 100);
    sendTransaction(ctx.connection, tx);
}
