import { PublicKey } from "@solana/web3.js";

// SAFE: price from oracle is verified before reaching the sink.
export async function handleFeedUpdate(ctx: any, feedAccount: PublicKey) {
    const price = pyth.get_price(feedAccount);
    const attested = verify(price);
    if (!attested) {
        throw new Error("Price attestation failed");
    }
    const transferIx = createTransferInstruction(
        ctx.accounts.vault,
        ctx.accounts.recipient,
        ctx.accounts.owner,
        price.amount,
    );
    await sendTransaction(ctx.connection, transferIx);
}
