// Steps 5a to 5d and 5g: the lock, signed with the setup key (DESIGN 7.3, 6.6).
// Source: https://xrpl.org/docs/references/protocol/transactions/types/signerlistset
// Source: https://xrpl.org/docs/references/protocol/transactions/types/accountset
// Source: https://xrpl.org/docs/references/protocol/transactions/types/depositpreauth
import { domain } from '@legx/core/dealcore';
import { multisigFee } from '@legx/core/fees';
import { type AccountSet, AccountSetAsfFlags, type DepositPreauth, type SignerListSet } from 'xrpl';
import { addr, type BuildCtx, baseFee, bytes32, distinct, hexUp } from './common.ts';

/** Fee for a transaction that `signers` accounts multisign: base x (1 + signers). Without `signers`, the base fee. */
const feeFor = (ctx: BuildCtx, signers?: number): string =>
  String(signers === undefined ? baseFee(ctx) : multisigFee(baseFee(ctx), signers));

/** The four classic signer accounts, weight 1 each, quorum 4. Rejects duplicates and the wallet itself. */
export function signerListFields(
  wallet: string,
  signers: readonly string[],
): Pick<SignerListSet, 'SignerQuorum' | 'SignerEntries'> {
  const list = signers.map(addr);
  if (list.length !== 4 || new Set(list).size !== 4) throw new Error('need four distinct signer accounts');
  if (list.includes(wallet)) throw new Error('the wallet cannot be its own signer');
  return { SignerQuorum: 4, SignerEntries: list.map((Account) => ({ SignerEntry: { Account, SignerWeight: 1 } })) };
}

/** 5a */
export function build5a(i: { shell: string; signers: readonly string[] }, ctx: BuildCtx): SignerListSet {
  const shell = addr(i.shell);
  return {
    TransactionType: 'SignerListSet',
    Account: shell,
    ...signerListFields(shell, i.signers),
    Fee: String(baseFee(ctx)),
  };
}

/** 5b: Domain = 01 || contractRoot || dealSeal (65 bytes), and DepositAuth on. */
export function build5b(
  i: { shell: string; contractRoot: Uint8Array; dealSeal: Uint8Array },
  ctx: BuildCtx,
): AccountSet {
  return {
    TransactionType: 'AccountSet',
    Account: addr(i.shell),
    Domain: hexUp(domain(bytes32('contractRoot', i.contractRoot), bytes32('dealSeal', i.dealSeal))),
    SetFlag: AccountSetAsfFlags.asfDepositAuth,
    Fee: String(baseFee(ctx)),
  };
}

const DISALLOW = {
  nftOffer: AccountSetAsfFlags.asfDisallowIncomingNFTokenOffer,
  check: AccountSetAsfFlags.asfDisallowIncomingCheck,
  payChannel: AccountSetAsfFlags.asfDisallowIncomingPayChan,
  trustLine: AccountSetAsfFlags.asfDisallowIncomingTrustline,
} as const;
export type DisallowKind = keyof typeof DISALLOW;
export const DISALLOW_KINDS = Object.keys(DISALLOW) as readonly DisallowKind[];

/** 5c: one DisallowIncoming flag per transaction (12, 13, 14, 15). */
export function build5c(i: { shell: string; kind: DisallowKind }, ctx: BuildCtx): AccountSet {
  const flag = DISALLOW[i.kind];
  if (flag === undefined) throw new Error(`unknown DisallowIncoming kind "${String(i.kind)}"`);
  return { TransactionType: 'AccountSet', Account: addr(i.shell), SetFlag: flag, Fee: String(baseFee(ctx)) };
}

/** 5d: the single DepositPreauth entry, for the sealed releaser account (D23). `signers` makes the multisigned fee. */
export function build5d(i: { shell: string; releaser: string; signers?: number }, ctx: BuildCtx): DepositPreauth {
  distinct('DepositPreauth', i.shell, i.releaser);
  return {
    TransactionType: 'DepositPreauth',
    Account: addr(i.shell),
    Authorize: addr(i.releaser),
    Fee: feeFor(ctx, i.signers),
  };
}

/** Replacing lawyer B (DESIGN 5.4): revokes the old releaser's preauth before `build5d` authorizes the new one. */
export function build5dUnauthorize(
  i: { shell: string; releaser: string; signers?: number },
  ctx: BuildCtx,
): DepositPreauth {
  distinct('DepositPreauth', i.shell, i.releaser);
  return {
    TransactionType: 'DepositPreauth',
    Account: addr(i.shell),
    Unauthorize: addr(i.releaser),
    Fee: feeFor(ctx, i.signers),
  };
}

/** Sets only `Domain` (the new seal after a replacement), with no flag. Usually multisigned by the new four. */
export function build5Domain(
  i: { shell: string; contractRoot: Uint8Array; dealSeal: Uint8Array; signers?: number },
  ctx: BuildCtx,
): AccountSet {
  return {
    TransactionType: 'AccountSet',
    Account: addr(i.shell),
    Domain: hexUp(domain(bytes32('contractRoot', i.contractRoot), bytes32('dealSeal', i.dealSeal))),
    Fee: feeFor(ctx, i.signers),
  };
}

/** 5g: the setup key's last use. */
export function build5g(i: { shell: string }, ctx: BuildCtx): AccountSet {
  return {
    TransactionType: 'AccountSet',
    Account: addr(i.shell),
    SetFlag: AccountSetAsfFlags.asfDisableMaster,
    Fee: String(baseFee(ctx)),
  };
}
