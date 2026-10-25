// Step 1: the contract NFT (DESIGN 6.12, 7.3).
// Source: https://xrpl.org/docs/references/protocol/transactions/types/nftokenmint
import { encodeMintMemo, MINT_MEMO_TYPE, type MintMemo, nftUri } from '@legx/core/signedContract';
import type { NFTokenMint } from 'xrpl';
import { addr, type BuildCtx, baseFee, bytes32 } from './common.ts';

/** 1: lawyer A's operations account mints a non-transferable NFT. 75-byte URI, one 195-byte memo. */
export function build1(
  i: { lawyerOpsA: string; signedContractSeal: Uint8Array; memo: MintMemo },
  ctx: BuildCtx,
): NFTokenMint {
  return {
    TransactionType: 'NFTokenMint',
    Account: addr(i.lawyerOpsA),
    NFTokenTaxon: 0,
    Flags: 0,
    URI: nftUri(bytes32('signedContractSeal', i.signedContractSeal)),
    Memos: [{ Memo: { MemoType: MINT_MEMO_TYPE, MemoData: encodeMintMemo(i.memo) } }],
    Fee: String(baseFee(ctx)),
  };
}
