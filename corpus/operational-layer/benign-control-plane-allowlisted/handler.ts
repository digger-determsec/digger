import { PublicKey } from "@solana/web3.js";

// SAFE: programId is fetched from off-chain config, but an allowlist check
// gates the routing target before the privileged sink executes.
export async function handleRoute(ctx: any) {
    const programId = fetchConfig("routing");
    if (ALLOWED_PROGRAMS.includes(programId)) {
        const tx = createTransferInstruction(
            ctx.accounts.vault,
            ctx.accounts.dest,
            programId,
            100,
        );
        await sendTransaction(ctx.connection, tx);
    }
}
