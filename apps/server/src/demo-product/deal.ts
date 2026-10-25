// One product-demo deal (build/PRODUCT_DEMO.md 2 to 4): the walkthrough engine's real deal, driven by staged approvals.
// The engine's steps run in T-I-01 order, so the human stages map onto them like this (DQ-P1 in the status file):
//   1 at creation: enroll, deal, contract (+ the PDF NFT minted by lawyer A's ops account)
//   2-5 (passports, keys): signed approvals; deal.ts makes the onboarding, DKG and PQ records after funding, so
//   6 runs funding, the NFT's sell offer to the deal wallet (before DisallowIncomingNFTokenOffer), then identity-keys
//   7 lock, 8 shipment, 9 receipt, 10 approval, 11 presence, 12 gate,
//   13 release + the deal wallet accepts the NFT (4-of-4; after the gate, whose lock check refuses an owned NFTokenPage)
//   14 the deal wallet hands the NFT to the sender (4-of-4 offer, sender accepts), then the AccountDelete close.
// Source: build/PRODUCT_DEMO.md; https://xrpl.org/docs/references/protocol/transactions/types/nftokenmint ;
// https://xrpl.org/docs/references/protocol/transactions/types/nftokencreateoffer ;
// https://xrpl.org/docs/references/protocol/transactions/types/nftokenacceptoffer ;
// https://xrpl.org/docs/references/protocol/transactions/types/accountdelete (an owned NFTokenPage blocks deletion)
import type { Finding } from '@legx/contracts/records';
import type { FastifyInstance } from 'fastify';
import type xrpl from 'xrpl';
import type { StepId } from '../demo-walkthrough/types.ts';
import { Walkthrough, type WalkthroughDeps, WalkthroughError } from '../demo-walkthrough/walkthrough.ts';
import { approvalFingerprint, type Participant, type PublicParticipant, pub } from './participants.ts';

type Actor = 'sender' | 'recipient' | 'auto';
type Work = StepId | 'nft-offer' | 'nft-accept' | 'nft-handoff';

const STAGES: readonly { name: string; actor: Actor; work: readonly Work[] }[] = [
  { name: 'Contract signed (PDF minted as NFT)', actor: 'auto', work: [] }, // runs in create()
  { name: 'Sender passport verified', actor: 'sender', work: [] },
  { name: 'Recipient passport verified', actor: 'recipient', work: [] },
  { name: 'Sender keys set up (FROST DKG + PQ binding)', actor: 'sender', work: [] },
  { name: 'Recipient keys set up', actor: 'recipient', work: [] },
  { name: 'Escrow funded (amount locked)', actor: 'sender', work: ['funding', 'nft-offer', 'identity-keys'] },
  { name: 'Wallet locked and checked', actor: 'auto', work: ['lock'] },
  { name: 'Shipment signed', actor: 'recipient', work: ['shipment'] },
  { name: 'Receipt signed', actor: 'sender', work: ['receipt'] },
  { name: 'Sender approves release', actor: 'sender', work: [] },
  { name: 'Recipient approves release', actor: 'recipient', work: ['presence'] },
  { name: 'Release gate (17 checks)', actor: 'auto', work: ['gate'] },
  { name: 'Funds released to recipient', actor: 'auto', work: ['release', 'nft-accept'] },
  { name: 'Wallet closed', actor: 'auto', work: ['nft-handoff', 'close'] },
];

interface By {
  readonly rid: string;
  readonly name: string;
  readonly at: string;
  readonly signatureFingerprint: string;
}
interface Stage {
  readonly n: number;
  readonly name: string;
  readonly actor: Actor;
  status: 'pending' | 'done' | 'failed';
  at?: string;
  by?: By;
  txHashes: string[];
  detail?: string;
}

export interface Pdf {
  readonly sha256: string;
  readonly url: string;
}

interface Opts {
  readonly sender: Participant;
  readonly recipient: Participant;
  readonly amountXrp: number;
  readonly terms: string;
  /** Stores the PDF under the deal's id. */
  readonly pdf: (id: string) => Pdf;
}

const hexOf = (s: string) => Buffer.from(s, 'utf8').toString('hex').toUpperCase();
const tfSellNFToken = 1; // Source: https://xrpl.org/docs/references/protocol/transactions/types/nftokencreateoffer
const tfTransferable = 8; // Source: https://xrpl.org/docs/references/protocol/transactions/types/nftokenmint

export class ProductDeal {
  readonly id: string;
  readonly createdAt = new Date().toISOString();
  readonly stages: Stage[];
  readonly nft = { id: '', mintTx: '', offer: '', owner: '' };
  readonly #w: Walkthrough;
  #gate: readonly Finding[] | undefined;

  readonly sender: Participant;
  readonly recipient: Participant;
  readonly amountXrp: number;
  readonly terms: string;
  readonly pdf: Pdf;

  private constructor(w: Walkthrough, o: Omit<Opts, 'pdf'>, pdf: Pdf) {
    this.#w = w;
    this.id = w.id;
    this.sender = o.sender;
    this.recipient = o.recipient;
    this.amountXrp = o.amountXrp;
    this.terms = o.terms;
    this.pdf = pdf;
    this.stages = STAGES.map((s, i) => ({ n: i + 1, name: s.name, actor: s.actor, status: 'pending', txHashes: [] }));
  }

  /** Makes the engine's deal with the sender in Alice's role and the recipient in Bob's, then runs stage 1. */
  static async create(app: FastifyInstance, deps: WalkthroughDeps, o: Opts): Promise<ProductDeal> {
    const w = await Walkthrough.create(
      app,
      deps,
      { amountXrp: o.amountXrp, identity: 'chip' },
      { sender: o.sender.wallet, recipient: o.recipient.wallet },
    );
    const p = new ProductDeal(w, o, o.pdf(w.id));
    await p.#stage(p.stages[0] as Stage, ['enroll', 'deal', 'contract'], async () => {
      const d = w.deal;
      const r = await w.chain.send(d.lawyerA.ops, {
        TransactionType: 'NFTokenMint',
        Account: d.lawyerA.ops.classicAddress,
        NFTokenTaxon: 0,
        Flags: tfTransferable,
        URI: hexOf(p.pdf.url),
        Memos: [{ Memo: { MemoType: hexOf('legx/contract-sha256'), MemoData: p.pdf.sha256.toUpperCase() } }],
      } as xrpl.SubmittableTransaction);
      Object.assign(p.nft, { id: String(r.meta.nftoken_id), mintTx: r.hash, owner: d.lawyerA.ops.classicAddress });
    });
    return p;
  }

  get dealId(): string {
    return this.#w.dealId;
  }
  get status(): 'locked' | 'released' {
    return this.#done(13) ? 'released' : 'locked';
  }
  #done = (n: number) => this.stages[n - 1]?.status === 'done';

  /** `who` approves stage `n`: 403 for a wrong actor, 409 for a wrong order; then the auto stages after it run. */
  async approve(who: Participant, n: number): Promise<void> {
    const s = this.stages[n - 1];
    if (!s) throw new WalkthroughError(400, 'invalid_request', `no stage ${n}`);
    const role = who.rid === this.sender.rid ? 'sender' : who.rid === this.recipient.rid ? 'recipient' : undefined;
    if (s.actor !== role) throw new WalkthroughError(403, 'wrong_actor', `stage ${n} is for the ${s.actor}`);
    const next = this.stages.find((x) => x.status !== 'done');
    if (next !== s || s.status === 'failed')
      throw new WalkthroughError(409, 'wrong_order', `the next stage is ${next ? next.n : 'none'}`);
    s.by = {
      rid: who.rid,
      name: who.name,
      at: new Date().toISOString(),
      signatureFingerprint: approvalFingerprint(who, this.id, n, who.rid),
    };
    await this.#stage(s, STAGES[n - 1]?.work ?? []);
    for (let t = this.stages[n]; t?.actor === 'auto' && t.status === 'pending'; t = this.stages[t.n])
      await this.#stage(t, STAGES[t.n - 1]?.work ?? []);
  }

  /** Runs one stage's work on the ledger, records it, and pushes a `walkthrough.step` feed row with the deal IDs. */
  async #stage(s: Stage, work: readonly Work[], extra?: () => Promise<void>): Promise<void> {
    const c = this.#w.chain;
    const from = c.log.length;
    try {
      for (const id of work) {
        if (id === 'nft-offer' || id === 'nft-accept' || id === 'nft-handoff') await this.#nft[id]();
        else if (!this.#w.steps.find((x) => x.id === id)?.skipped) {
          const r = await this.#w.next();
          if (r.status !== 'ok') throw new Error(r.detail);
          if (r.gate) this.#gate = r.gate;
        }
      }
      await extra?.();
      s.status = 'done';
    } catch (e) {
      s.status = 'failed';
      s.detail = e instanceof Error ? e.message : String(e);
    }
    s.at = new Date().toISOString();
    s.txHashes = c.log.slice(from).map((l) => l.hash);
    await this.#w.row({ productDealId: this.id, dealId: this.dealId, stage: s, status: this.status });
    if (s.status === 'failed') throw new WalkthroughError(502, 'stage_failed', `stage ${s.n}: ${s.detail}`);
  }

  // The NFT's way into the deal wallet and out of it before AccountDelete.
  readonly #nft = {
    'nft-offer': async () => {
      const d = this.#w.deal;
      const r = await this.#w.chain.send(d.lawyerA.ops, {
        TransactionType: 'NFTokenCreateOffer',
        Account: d.lawyerA.ops.classicAddress,
        NFTokenID: this.nft.id,
        Amount: '0',
        Flags: tfSellNFToken,
        Destination: d.wallet,
      });
      this.nft.offer = String(r.meta.offer_id);
    },
    'nft-accept': async () => {
      const d = this.#w.deal;
      await d.multi4({ TransactionType: 'NFTokenAcceptOffer', Account: d.wallet, NFTokenSellOffer: this.nft.offer });
      this.nft.owner = await this.#ownerOf(d.wallet);
    },
    'nft-handoff': async () => {
      const d = this.#w.deal;
      const r = await d.multi4({
        TransactionType: 'NFTokenCreateOffer',
        Account: d.wallet,
        NFTokenID: this.nft.id,
        Amount: '0',
        Flags: tfSellNFToken,
        Destination: this.sender.xrplAddress,
      });
      await this.#w.chain.send(this.sender.wallet, {
        TransactionType: 'NFTokenAcceptOffer',
        Account: this.sender.xrplAddress,
        NFTokenSellOffer: String(r.meta.offer_id),
      });
    },
  };

  /** `account` if it holds the NFT on the validated ledger. Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_nfts */
  async #ownerOf(account: string): Promise<string> {
    const r = await this.#w.chain.client.request({ command: 'account_nfts', account, ledger_index: 'validated' });
    if (!r.result.account_nfts.some((n) => n.NFTokenID === this.nft.id))
      throw new Error(`${account} does not hold ${this.nft.id}`);
    return account;
  }

  close = () => this.#w.close();

  summary() {
    const by = (ns: number[]) => {
      const list = ns.flatMap((n) => (this.stages[n - 1]?.by ? [this.stages[n - 1]?.by as By] : []));
      return { done: list.length, of: 2, by: list };
    };
    const short = (b: { by: By[] }) => ({ ...b, by: b.by.map(({ rid, name, at }) => ({ rid, name, at })) });
    const tx = (n: number, i: number) => this.stages[n - 1]?.txHashes.at(i);
    const approvals = by([10, 11]);
    const fundTx = this.#fundTx();
    return {
      id: this.id,
      dealId: this.dealId,
      createdAt: this.createdAt,
      status: this.status,
      sender: pub(this.sender) as PublicParticipant,
      recipient: pub(this.recipient) as PublicParticipant,
      amountXrp: this.amountXrp,
      terms: this.terms,
      contract: {
        sha256: this.pdf.sha256,
        pdfUrl: this.pdf.url,
        nftId: this.nft.id,
        nftOwner: this.nft.owner,
        mintTx: this.nft.mintTx,
      },
      escrow: {
        status: this.#done(13) ? 'released' : this.#done(6) ? 'locked' : 'not funded',
        amountXrp: this.amountXrp,
        walletAddress: this.#w.deal.wallet,
        ...(fundTx ? { fundTx } : {}),
        ...(this.#done(13) ? { releaseTx: tx(13, 0) } : {}),
        ...(this.#done(14) ? { closeTx: tx(14, -1) } : {}),
        keys: short(by([4, 5])),
        passports: short(by([2, 3])),
        approvals,
      },
      stages: this.stages.map(({ detail: _, ...s }) => s),
      ...(this.#gate ? { gate: { passed: this.#gate.every((f) => f.ok), findings: this.#gate } } : {}),
      ...(this.#done(13)
        ? {
            releasedAt: this.stages[12]?.at,
            releasedBy: approvals.by.map(({ rid, name, signatureFingerprint }) => ({
              rid,
              name,
              signatureFingerprint,
            })),
          }
        : {}),
      ledger: { network: 'standalone' },
    };
  }

  /** The EscrowCreate of stage 6 (the funding step's last transaction). */
  #fundTx(): string | undefined {
    const r = this.#w.results.find((x) => x.step === 'funding');
    return r?.txHashes.at(-1);
  }
}
