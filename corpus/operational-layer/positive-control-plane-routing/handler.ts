import { PublicKey } from "@solana/web3.js";

// BUG: programId is fetched from off-chain config and used to route a CPI
// call without any allowlist or owner check gating the target program.
export async function handleRoute(ctx: any) {
    const programId = fetchConfig("routing");
    const tx = createTransferInstruction(
        ctx.accounts.vault,
        ctx.accounts.dest,
        programId,
        100,
    );
    await sendTransaction(ctx.connection, tx);
}
