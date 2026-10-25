// Lawyer buttons that act on the deal itself: sign the contract, bind the operations account, mint the contract NFT
// (A), make the release code (B). Each signature goes through the approval prompt (approval.ts).
// Source: DESIGN 6.12 (signed contract), 6.14 (operations binding), 5.3 phases P6 and P7, OD-28

import { contractRoot } from '@legx/core/contract';
import { bytesToHex, hexToBytes, makeCondition, randomBytes, tupleHash, utf8ToBytes } from '@legx/core/dealcore';
import { escrowFinishFee } from '@legx/core/fees';
import { opsBindMsg, verifyOpsBinding } from '@legx/core/opsBinding';
import { PACKAGE_SUITES, type SealedPackage, XWING_SUITE } from '@legx/core/pq';
import { buildSignedContractSeal, type LawyerRole, MINT_MEMO_TYPE, signContract } from '@legx/core/signedContract';
import { encode, encodeForSigning } from 'xrpl';
import { type Described, signWithApproval } from './approval.ts';
import { createEventAppender } from './events.ts';
import { type ConsoleDeps, ConsoleError } from './ports.ts';

const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();
const LAST_LEDGER_OFFSET = 20;
const MINT_FEE = '10';

export function createDealActions(deps: ConsoleDeps) {
  const { role, deal } = deps;
  const data = deal.data;
  const isA = role === 'LA';
  const myPub = isA ? data.lawyerPubA : data.lawyerPubB;
  const myCommitment = isA ? data.lawyerCommitmentA : data.lawyerCommitmentB;
  const sign = (request: Parameters<typeof signWithApproval>[1], claimed?: Described) =>
    signWithApproval(deps, request, claimed);
  let preimage: Uint8Array | undefined;
  const appendEvent = createEventAppender(deps);

  /** The root the console computes itself from the clauses it was given, refused if it is not the sealed one. */
  const rootOf = (): Uint8Array => {
    const root = contractRoot(deal.contract.clauses, deal.contract.salts);
    if (bytesToHex(root) !== data.contractRoot.toLowerCase()) throw new ConsoleError('ROOT_MISMATCH');
    return root;
  };

  /** Signs one transaction with the operations account key alone and submits it (mint and finish are single-signed). */
  async function submitSingle(tx: Record<string, unknown>) {
    const header = await deps.publicLedger.latest();
    const full = {
      ...tx,
      Account: deps.ops.address,
      Sequence: await deps.ledger.accountSequence(deps.ops.address),
      LastLedgerSequence: header.index + LAST_LEDGER_OFFSET,
      SigningPubKey: deps.ops.pubHex,
    };
    // Source: https://xrpl.org/docs/references/protocol/binary-format (signing: the signature is over the "STX\0" encoding)
    const signature = await deps.ops.sign(hexToBytes(encodeForSigning(full as never)));
    return deps.ledger.submit(encode({ ...full, TxnSignature: up(signature) } as never));
  }

  return {
    appendEvent,
    submitSingle,

    /** P4.4-01: what the lawyer reads before signing, all computed here. */
    contractView() {
      const root = rootOf();
      return {
        text: deal.contract.clauses.map((c) => new TextDecoder().decode(c)).join('\n\n'),
        wallet: data.walletAddress,
        rootHex: bytesToHex(root),
      };
    },

    /** Signs `contractSigMsg` with the lawyer slot; core refuses a signature that does not verify under the sealed key. */
    async signContract(): Promise<Uint8Array> {
      const terms = {
        contractRoot: rootOf(),
        walletAddress: data.walletAddress,
        lawyerPubA: data.lawyerPubA,
        lawyerPubB: data.lawyerPubB,
      };
      return signContract(
        () =>
          sign({
            kind: 'tagged',
            tag: 'legx/contract-sign/v1',
            parts: [terms.contractRoot, utf8ToBytes(terms.walletAddress), utf8ToBytes(role)],
          }),
        terms,
        role as LawyerRole,
      );
    },

    /** Lawyer A: NFTokenMint from ops A with the seal in the URI and both signatures in the memo (DESIGN 6.12). */
    async mintContractNft(sigLA: Uint8Array, sigLB: Uint8Array) {
      if (!isA) throw new ConsoleError('NOT_LAWYER_A');
      const { uriHex, memoHex } = buildSignedContractSeal(
        {
          contractRoot: rootOf(),
          walletAddress: data.walletAddress,
          lawyerPubA: data.lawyerPubA,
          lawyerPubB: data.lawyerPubB,
        },
        { sigLA, sigLB },
      );
      return submitSingle({
        TransactionType: 'NFTokenMint',
        NFTokenTaxon: 0,
        Flags: 0,
        URI: uriHex,
        Fee: MINT_FEE,
        Memos: [{ Memo: { MemoType: MINT_MEMO_TYPE, MemoData: memoHex } }],
      });
    },

    /** DESIGN 6.14: the ops account and the lawyer slot both sign one message; the binding is checked on a validated ledger. */
    async bindOperationsAccount() {
      const terms = {
        contractRoot: rootOf(),
        opsAccount: deps.ops.address,
        lawyerPub: myPub,
        lawyerCommitment: hexToBytes(myCommitment),
        role: role as LawyerRole,
      };
      const msg = opsBindMsg(terms);
      const lawyerSig = await sign({
        kind: 'tagged',
        tag: 'legx/ops-binding/v1',
        parts: [
          terms.contractRoot,
          utf8ToBytes(terms.opsAccount),
          hexToBytes(myPub),
          terms.lawyerCommitment,
          utf8ToBytes(role),
        ],
      });
      const opsSig = await deps.ops.sign(msg);
      const binding = { ...terms, opsPub: deps.ops.pubHex, opsSig: up(opsSig), lawyerSig: up(lawyerSig) };
      const account = (await deps.ledger.snapshot(deal.id)).ledger.opsAccounts[role];
      const checked = verifyOpsBinding(account, binding);
      if (!checked.ok) throw new ConsoleError(`OPS_BINDING_${checked.code}`);
      await appendEvent('ops.bound', {
        role,
        ops_account: terms.opsAccount,
        ops_pub: binding.opsPub,
        lawyer_pub: myPub,
        bar_commitment: myCommitment,
        sig_ops: binding.opsSig,
        sig_lawyer: binding.lawyerSig,
      });
      return binding;
    },

    /**
     * Lawyer B: makes the 32-byte release code in the browser. Only the condition leaves the console (P4.4-02); the code
     * itself appears again only inside the EscrowFinish.
     */
    async makeReleaseCode() {
      if (isA) throw new ConsoleError('NOT_LAWYER_B');
      preimage = randomBytes(32);
      const { condition } = makeCondition(preimage);
      await deps.evidence.condition(condition);
      return { condition, display: up(preimage).match(/.{8}/g)?.join(' ') ?? '' };
    },
    hasReleaseCode: () => preimage !== undefined,
    /** The condition this console's code opens. */
    condition(): string {
      if (!preimage) throw new ConsoleError('NO_RELEASE_CODE');
      return makeCondition(preimage).condition;
    },
    /** The `Fulfillment` for the EscrowFinish. Throws when the code was never made in this console. */
    fulfillment(): string {
      if (!preimage) throw new ConsoleError('NO_RELEASE_CODE');
      return makeCondition(preimage).fulfillment;
    },

    /** OD-28: hands the code to the new lawyer B, sealed to its X-Wing key. */
    async handoverReleaseCode(newLawyerPublicKey: Uint8Array): Promise<SealedPackage> {
      if (!preimage) throw new ConsoleError('NO_RELEASE_CODE');
      const suite = PACKAGE_SUITES[XWING_SUITE];
      if (!suite) throw new ConsoleError('SUITE_UNKNOWN');
      const sealed = await suite.seal(newLawyerPublicKey, preimage, utf8ToBytes(HANDOVER_INFO), handoverAad(deal.id));
      return { suite: XWING_SUITE, ...sealed };
    },
    async receiveReleaseCode(pkg: SealedPackage, secretKey: Uint8Array): Promise<void> {
      const suite = PACKAGE_SUITES[pkg.suite];
      if (!suite) throw new ConsoleError('SUITE_UNKNOWN');
      const code = await suite
        .open(secretKey, pkg.enc, pkg.ct, utf8ToBytes(HANDOVER_INFO), handoverAad(deal.id))
        .catch(() => {
          throw new ConsoleError('OPEN_FAILED');
        });
      if (code.length !== 32) throw new ConsoleError('OPEN_FAILED');
      preimage = code;
    },

    /** Both lawyers: approve an exit (a Payment or AccountDelete the coordinator proposes) with the slot and the HSM. */
    async approveExit(tx: Record<string, unknown>, claimed?: Described): Promise<string> {
      return up(await sign({ kind: 'xrpl-multisign', tx }, claimed));
    },

    finishFee: () => String(escrowFinishFee(10, 36, 0)),
  };
}

const HANDOVER_INFO = 'legx/hpke/release-code-handover/v1';
const handoverAad = (dealId: string) => tupleHash(HANDOVER_INFO, [utf8ToBytes(dealId)]);
export type DealActions = ReturnType<typeof createDealActions>;
