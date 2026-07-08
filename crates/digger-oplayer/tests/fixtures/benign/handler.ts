// Benign sibling: same handler structure, but the VAA signature IS verified
// before the price reaches the privileged sink.
//
// SAFE: verification check targets the external data variable, so the
// detector recognizes the attestation is validated.

import { PublicKey } from "@solana/web3.js";

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
