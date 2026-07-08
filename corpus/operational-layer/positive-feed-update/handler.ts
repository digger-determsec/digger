import { PublicKey } from "@solana/web3.js";

export async function handleFeedUpdate(ctx: any, feedAccount: PublicKey) {
    const price = pyth.get_price(feedAccount);
    const transferIx = createTransferInstruction(
        ctx.accounts.vault,
        ctx.accounts.recipient,
        ctx.accounts.owner,
        price.amount,
    );
    await sendTransaction(ctx.connection, transferIx);
}
