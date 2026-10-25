// What the phone computes itself before it signs (DESIGN 7.5, 10.1): the seal from the public deal data, and the
// transaction's real fields from its own bytes. Nothing here reads the coordinator's description of a transaction.
// xrpl is loaded with a dynamic import() only, so it stays out of the entry bundle.
// Source: https://xrpl.org/docs/references/protocol/binary-format (encode/decode of the canonical binary form)
// Source: https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/accountroot (lsfRequireDestTag)
import type { SignatureRequest } from '@legx/contracts/api';
import type { PublicDealData } from '@legx/contracts/deal';
import type { z } from 'zod';
import { checkSeal } from '../../lib/seal.ts';

const LSF_REQUIRE_DEST_TAG = 0x00020000;

type Request = z.infer<typeof SignatureRequest>;

type DecodedTx = {
  type: string;
  account: string;
  destination?: string;
  tag?: number;
  amountDrops?: string;
  fields: Record<string, unknown>;
};

/** The transaction as its own canonical bytes say it is (encode, then decode: nothing else survives). */
async function decodeTx(tx: Record<string, unknown>): Promise<DecodedTx> {
  const { encode, decode } = await import('xrpl');
  const f = decode(encode(tx as never)) as Record<string, unknown>;
  const amount = typeof f.Amount === 'string' ? f.Amount : undefined;
  return {
    type: String(f.TransactionType),
    account: String(f.Account),
    ...(typeof f.Destination === 'string' ? { destination: f.Destination } : {}),
    ...(typeof f.DestinationTag === 'number' ? { tag: f.DestinationTag } : {}),
    ...(amount ? { amountDrops: amount } : {}),
    fields: f,
  };
}

const parsePayout = (p: string): { account: string; tag?: number } => {
  const [account = '', tag] = p.split(':');
  return { account, ...(tag === undefined ? {} : { tag: Number(tag) }) };
};

export type ExitView =
  | {
      ok: true;
      type: string;
      destination: string;
      tag?: number;
      amountDrops?: string;
      wallet: string;
      dealId: string;
      warnings: string[];
    }
  | { ok: false; code: string; message: string };

const refuse = (code: string, message: string): ExitView => ({ ok: false, code, message });

export type ExitInput = {
  dealId: string;
  request: Request;
  publicData: PublicDealData;
  /** The seals the coordinator claims (public-data and deal view). */
  claimedSeals: readonly (string | undefined)[];
  /** The deal's agreed amount, from the sealed deal view. */
  amountDrops: string;
  /** The coordinator's validated `account_info` relay for an address (undefined when the account does not exist). */
  accountInfo: (address: string) => Promise<{ flags: number } | undefined>;
};

/** Decode the exit and compare it with the seal. Refuses, with a reason the screen shows, on any difference. */
export async function checkExit(i: ExitInput): Promise<ExitView> {
  if (!checkSeal(i.publicData, i.claimedSeals)) return refuse('SEAL_MISMATCH', 'Seal mismatch');
  if (i.request.dealId !== i.dealId) return refuse('WRONG_DEAL', 'This request is for another deal. Nothing to sign.');
  let tx: DecodedTx;
  try {
    tx = await decodeTx(i.request.unsignedTx);
  } catch {
    return refuse('TX_UNREADABLE', 'The transaction cannot be read. Nothing to sign.');
  }
  if (tx.account !== i.publicData.walletAddress)
    return refuse('WRONG_WALLET', 'It does not spend from your deal wallet.');
  const sealed = parsePayout(
    i.request.purpose === 'pay_bob' ? i.publicData.payoutB : i.publicData.payoutA, // refund and close go to Alice
  );
  const isPayment = i.request.purpose === 'pay_bob' || i.request.purpose === 'refund_alice';
  if (!isPayment && i.request.purpose !== 'close') return refuse('NOT_AN_EXIT', 'This is not a payment or a close.');
  if (tx.type !== (i.request.purpose === 'close' ? 'AccountDelete' : 'Payment'))
    return refuse('WRONG_TYPE', 'The transaction type does not match the request.');
  if (tx.destination !== sealed.account || tx.tag !== sealed.tag)
    return refuse('DESTINATION_NOT_SEALED', 'The destination is not the payout address sealed in your deal.');
  if (isPayment && tx.amountDrops !== i.amountDrops)
    return refuse('AMOUNT_MISMATCH', 'The amount is not the amount your deal agreed.');
  const warnings: string[] = [];
  const info = await i.accountInfo(sealed.account).catch(() => undefined);
  if (info && (info.flags & LSF_REQUIRE_DEST_TAG) !== 0 && sealed.tag === undefined)
    warnings.push('This account requires a destination tag, and your deal has none. The payment may be rejected.');
  return {
    ok: true,
    type: tx.type,
    destination: sealed.account,
    ...(sealed.tag === undefined ? {} : { tag: sealed.tag }),
    ...(tx.amountDrops ? { amountDrops: tx.amountDrops } : {}),
    wallet: tx.account,
    dealId: i.dealId,
    warnings,
  };
}

/** `wallet.sign(tx, true).tx_blob` for a multisigner: the transaction with one Signers entry and no secrets. */
export async function signerBlob(tx: Record<string, unknown>, signature: string, publicKey: string): Promise<string> {
  const { encode, deriveAddress } = await import('xrpl');
  const signed = {
    ...tx,
    SigningPubKey: '',
    Signers: [{ Signer: { Account: deriveAddress(publicKey), SigningPubKey: publicKey, TxnSignature: signature } }],
  };
  return encode(signed as never);
}
