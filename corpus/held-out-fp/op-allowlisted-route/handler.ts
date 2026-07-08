import { PublicKey } from "@solana/web3.js";

// SAFE: routing target from config is allowlisted before the sink.
export async function handleRoute(ctx: any) {
    const programId = fetchConfig("routing");
    if (ALLOWED_PROGRAMS.includes(programId)) {
        const tx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.dest, programId, 100);
        sendTransaction(ctx.connection, tx);
    }
}
