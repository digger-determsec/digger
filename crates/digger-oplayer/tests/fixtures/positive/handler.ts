// Positive fixture: feed/keeper handler that consumes a signed price from
// Pyth and routes it to a privileged action (token transfer) WITHOUT
// verifying the VAA signature or attestation on the data path.
//
// Vulnerable pattern: external data reaches a privileged sink with no
// cryptographic attestation check between source and sink.

import { PublicKey } from "@solana/web3.js";

// BUG: reads a price from an external feed (Pyth/Hermes)
// and uses it to drive a token transfer without verifying the price
// was actually attested by a valid oracle signature.
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
