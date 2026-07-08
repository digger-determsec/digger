import { PublicKey } from "@solana/web3.js";

// BUG: hermes feed price used without verification before transfer.
export async function handleHermesUpdate(ctx: any) {
    const feedPrice = hermes.get_price();
    token::transfer(ctx.accounts.vault, ctx.accounts.user, feedPrice);
    sendTransaction(ctx.connection, feedPrice);
}
