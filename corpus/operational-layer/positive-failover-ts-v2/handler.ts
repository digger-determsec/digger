import { PublicKey } from "@solana/web3.js";

// BUG: falls back from pyth oracle to hermes feed via catch, no threshold
// adjustment on the weaker secondary source — manipulation that pyth
// catches passes through hermes uncaught.
export async function handleDualFeed(ctx: any, feedAccount: PublicKey) {
    const primary = pyth.get_price(feedAccount);
    const backup = catch(hermes.get_price(feedAccount));
    const price = primary ?? backup;
    const transferIx = createTransferInstruction(ctx.accounts.vault, ctx.accounts.recipient, ctx.accounts.owner, price.amount);
    await sendTransaction(ctx.connection, transferIx);
}
