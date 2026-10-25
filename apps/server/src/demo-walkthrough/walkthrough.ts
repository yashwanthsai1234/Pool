// One walkthrough: the T-I-01 role script (packages/xrpl/test-int/deal.ts and roles.ts, imported by relative path as
// demo-attacks does) on the server's ledger, run one step per `next`. Each step calls what full-flow.int.test.ts calls,
// in the same order; the coordinator sees the deal through its own API (deals.create signed with the demo lawyer A key,
// read back with the observer key), and every step adds a `walkthrough.step` row to the deal's live feed.
// Source: build/WALKTHROUGH.md; packages/xrpl/test-int/full-flow.int.test.ts (runFlow)
import { existsSync, readFileSync } from 'node:fs';
import type { FastifyInstance } from 'fastify';
import pg from 'pg';
import { standaloneEnv, testnetEnv } from '../../../../packages/xrpl/src/env.ts';
import { Deal } from '../../../../packages/xrpl/test-int/deal.ts';
import { type Chain, type ClientBase, makeClient, openChain } from '../../../../packages/xrpl/test-int/roles.ts';
import { type DemoKey, demoSigner } from '../../../../scripts/demo/sign.ts';
import { plan } from './steps.ts';
import {
  STEP_TOPIC,
  type StepId,
  type StepInfo,
  type StepResult,
  type WalkthroughInput,
  type WalkthroughState,
} from './types.ts';

export interface WalkthroughDeps {
  /** The ledger the server uses (standalone in the demo profile). */
  readonly ledgerWs: string;
  readonly network: 'standalone' | 'testnet';
  /** The server's Postgres: the feed rows go to its outbox. */
  readonly pgUrl: string;
  /** demo/state.json from `pnpm demo:seed`: the demo enrollment keys. */
  readonly statePath: string;
  /** The seed's keys as read at server start, the moment the coordinator pinned them; a later re-seed must not change what we sign with. */
  seed?: { observer: DemoKey; keys: Record<string, DemoKey> };
  /** build/tmp/ship-core-ready: when present at creation, the shipment and receipt steps run (OD-38). */
  readonly shipReadyFlag: string;
}

/** A refusal the routes turn into an HTTP status. */
export class WalkthroughError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** The XRPL accounts that take Alice's and Bob's roles, when the caller has its own (the product demo's participants). */
export interface Parties {
  readonly sender: ClientBase['wallet'];
  readonly recipient: ClientBase['wallet'];
}

type Out = Omit<StepResult, 'step' | 'n' | 'status' | 'txHashes' | 'ledgerIndex'>;

const XRP = 1_000_000;
const explorer = (h: string) => `https://testnet.xrpl.org/transactions/${h}`;

export class Walkthrough {
  readonly id = crypto.randomUUID();
  readonly input: WalkthroughInput;
  readonly steps: readonly StepInfo[];
  readonly #c: Chain;
  readonly #d: WalkDeal;
  readonly #deps: WalkthroughDeps;
  readonly #api: Api;
  readonly #feed: pg.Pool;
  readonly results: StepResult[] = [];
  dealId = '';
  status: WalkthroughState['status'] = 'ready';
  #gate: Awaited<ReturnType<Deal['gate']>> | undefined;

  private constructor(deps: WalkthroughDeps, input: WalkthroughInput, c: Chain, d: WalkDeal, api: Api) {
    this.#deps = deps;
    this.input = input;
    this.#c = c;
    this.#d = d;
    this.#api = api;
    this.#feed = new pg.Pool({ connectionString: deps.pgUrl, max: 1 });
    this.steps = plan(existsSync(deps.shipReadyFlag));
  }

  /** Opens the ledger connection, makes the deal's roles, and creates the deal in the coordinator (lawyer A signs). */
  static async create(
    app: FastifyInstance,
    deps: WalkthroughDeps,
    input: WalkthroughInput,
    parties?: Parties,
  ): Promise<Walkthrough> {
    const escrowDrops = String(Math.round(input.amountXrp * XRP));
    if (!existsSync(deps.statePath))
      throw new WalkthroughError(409, 'not_seeded', `no ${deps.statePath}: run pnpm demo:seed first`);
    const c = await openChain(deps.network === 'testnet' ? testnetEnv() : standaloneEnv(deps.ledgerWs));
    try {
      const d = new WalkDeal(c, escrowDrops, parties);
      const w = new Walkthrough(deps, input, c, d, api(app, c, deps));
      const view = await w.#api.call<{ dealId: string }>('lawyer-a', 'POST', '/deals', {
        network: deps.network,
        identityPolicy: input.identity,
        amountDrops: escrowDrops,
        payoutA: `${d.aliceBase.wallet.classicAddress}:7`,
        payoutB: d.bobBase.wallet.classicAddress,
        lawyerOpsA: d.baseA.ops.classicAddress,
        lawyerOpsB: d.baseB.ops.classicAddress,
      });
      w.dealId = view.dealId;
      return w;
    } catch (e) {
      await c.close();
      throw e;
    }
  }

  /** The ledger and the T-I-01 deal, for a caller that adds its own ledger work between steps (the product demo). */
  get chain(): Chain {
    return this.#c;
  }
  get deal(): WalkDeal {
    return this.#d;
  }

  state(): WalkthroughState {
    return {
      id: this.id,
      dealId: this.dealId,
      ledgerDealId: this.#d.dealId,
      wallet: this.#d.wallet,
      network: this.#deps.network,
      input: this.input,
      steps: this.steps,
      results: this.results,
      status: this.status,
    };
  }

  /** Runs exactly one step: the first runnable one without a result. */
  async next(): Promise<StepResult> {
    if (this.status === 'failed') throw new WalkthroughError(409, 'walkthrough_failed', 'a step failed; start again');
    const done = new Set(this.results.map((r) => r.step));
    const step = this.steps.find((s) => !s.skipped && !done.has(s.id));
    if (!step) throw new WalkthroughError(409, 'walkthrough_done', 'every step has run');
    this.status = 'running';
    const from = this.#c.log.length;
    let out: Out;
    let ok = true;
    try {
      out = await this.#c.step(step.title, () => this.#run[step.id]());
    } catch (e) {
      ok = false;
      out = { detail: e instanceof Error ? e.message : String(e) };
    }
    const logged = this.#c.log.slice(from);
    ok &&= logged.every((l) => l.result === 'tesSUCCESS');
    const txHashes = logged.map((l) => l.hash);
    const result: StepResult = {
      step: step.id,
      n: step.n,
      status: ok ? 'ok' : 'failed',
      txHashes,
      ...(this.#deps.network === 'testnet' ? { explorer: txHashes.map(explorer) } : {}),
      ledgerIndex: (await this.#c.lcl()).index,
      ...out,
      detail: `${out.detail} (${step.holders})`,
    };
    this.results.push(result);
    this.status = !ok
      ? 'failed'
      : this.steps.every((s) => s.skipped || done.has(s.id) || s.id === step.id)
        ? 'done'
        : 'ready';
    await this.row({ walkthroughId: this.id, dealId: this.dealId, ...result });
    if (this.status !== 'ready') await this.#c.close(); // the feed stays open for the caller's last rows
    return result;
  }

  async close(): Promise<void> {
    await this.#c.close();
    await this.#feed.end().catch(() => undefined);
  }

  /** One `walkthrough.step` row of the deal's feed, at the deal's next seq (the outbox trigger wakes the feed). */
  async row(body: object): Promise<void> {
    const payload = Buffer.from(JSON.stringify(body));
    const db = await this.#feed.connect();
    try {
      await db.query('begin');
      // the same per-deal lock as OutboxRepo.enqueueNext, so a coordinator write and this row never share a seq
      await db.query(`select pg_advisory_xact_lock(hashtextextended('outbox:' || $1, 0))`, [this.dealId]);
      await db.query(
        `insert into outbox (topic, payload, deal_id, seq)
         select $1, $2, $3::uuid, coalesce(max(seq) + 1, 0) from outbox where deal_id = $3::uuid`,
        [STEP_TOPIC, payload, this.dealId],
      );
      await db.query('commit');
    } catch (e) {
      await db.query('rollback').catch(() => undefined);
      throw e;
    } finally {
      db.release();
    }
  }

  // The steps. Each is the code of runFlow (full-flow.int.test.ts) and deal.ts STAGES, in their order.
  readonly #run: Record<StepId, () => Promise<Out>> = {
    enroll: async () => {
      await this.#d.advance('onboarded');
      return { detail: 'verifier, Alice, Bob and both lawyers funded; LEGX_ATTORNEY issued and accepted' };
    },
    deal: async () => {
      const v = await this.#api.call<{ state: string }>('observer', 'GET', `/deals/${this.dealId}`);
      return { detail: `coordinator deal ${this.dealId} is ${v.state} (deals.create signed by lawyer A)` };
    },
    contract: async () => {
      await this.#d.advance('contract');
      return { detail: `signed-contract NFT ${this.#d.minted.nftokenId} minted by lawyer A` };
    },
    funding: async () => {
      await this.#d.advance('funded');
      return {
        detail: `wallet ${this.#d.wallet} opened; escrow ${this.#d.escrowSequence} holds ${this.#d.escrowDrops} drops`,
      };
    },
    'identity-keys': async () => {
      await this.#d.advance('keys');
      const ident =
        this.input.identity === 'chip'
          ? 'fixture chip onboarding records'
          : 'onboarding records (the T-I-01 script records the chip path; the ZK path is T-I-12)';
      return { detail: `${ident}; FROST DKG for slots A, LA, B, LB; PQ bindings for all 4` };
    },
    lock: async () => {
      await this.#d.advance('locked');
      const findings = await this.#d.lockCheck();
      // runFlow: the wiped setup key can no longer sign for the wallet (DisableMaster)
      const refused = await this.#c.submitBlob(
        this.#d.shell.sign(
          await this.#c.client.autofill({ TransactionType: 'AccountSet', Account: this.#d.wallet, Domain: '00' }),
        ).tx_blob,
      );
      const code = refused.status === 'rejected' ? refused.result : refused.status;
      if (code !== 'tefMASTER_DISABLED') throw new Error(`the wiped setup key was not refused: ${code}`);
      return {
        detail: `lock checker ${findings.filter((f) => f.ok).length}/${findings.length} ok; setup key refused ${code}`,
      };
    },
    // OD-37: Bob's slot B signs shipMsg, Alice's slot A signs rcptMsg over that shipment (build/SHIP_RECEIPT.md 2, 3).
    shipment: async () => {
      const d = this.#d;
      await d.ship();
      const sh = d.shipped as NonNullable<typeof d.shipped>;
      return { detail: `shipment ${hex(sh.hash).slice(0, 16)} signed by slot B at ledger ${sh.ledgerIndex}` };
    },
    receipt: async () => {
      const d = this.#d;
      await d.receive();
      return { detail: 'receipt (condition ok) signed by slot A' };
    },
    presence: async () => {
      const input = await this.#d.readInput();
      return { detail: `release attestations for sides ${Object.keys(input.records.passport).join(', ')}` };
    },
    gate: async () => {
      this.#gate = await this.#d.gate();
      if (this.#gate.failing.length > 0) throw new Error(`gate failing: ${this.#gate.failing.join(', ')}`);
      return { detail: `${this.#gate.findings.length} codes pass`, gate: this.#gate.findings };
    },
    release: async () => {
      if (!this.#gate) throw new Error('the gate has not run');
      const record = await this.#gate.record();
      await this.#c.send(this.#d.lawyerB.ops, this.#d.finishTx({ leaf: record.leafHash }));
      const exit = await this.#d.exit('bob');
      const gained = exit.receiverAfter - exit.receiverBefore;
      return {
        detail: `EscrowFinish with the gate memo, then 4-of-4 payment: Bob +${gained} drops`,
        bob: { before: String(exit.receiverBefore), after: String(exit.receiverAfter) },
      };
    },
    close: async () => {
      await this.#d.closeShell();
      try {
        await this.#c.client.request({ command: 'account_info', account: this.#d.wallet, ledger_index: 'validated' });
      } catch (e) {
        if ((e as { data?: { error?: string } }).data?.error === 'actNotFound')
          return { detail: `wallet ${this.#d.wallet} deleted, its balance went to Alice` };
        throw e;
      }
      throw new Error(`wallet ${this.#d.wallet} still exists`);
    },
  };
}

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

/** The T-I-01 deal plus the OD-37 shipment and receipt records, which the release gate reads with the rest. */
export class WalkDeal extends Deal {
  override readonly aliceBase: ClientBase;
  override readonly bobBase: ClientBase;

  constructor(c: Chain, escrowDrops: string, parties?: Parties) {
    super(c, { escrowDrops });
    // A role keeps its demo passport and slot; only its XRPL account is the caller's.
    const base = (side: 'A' | 'B', w?: Parties['sender']) => ({ ...makeClient(side), ...(w ? { wallet: w } : {}) });
    this.aliceBase = base('A', parties?.sender);
    this.bobBase = base('B', parties?.recipient);
  }
}

interface Api {
  call<T>(who: 'lawyer-a' | 'observer', method: 'GET' | 'POST', path: string, body?: unknown): Promise<T>;
}

/** The coordinator through its own HTTP API, in process (`inject`), signed with the demo enrollment keys (OD-5). */
function api(app: FastifyInstance, c: Chain, deps: WalkthroughDeps): Api {
  const st = deps.seed ?? (JSON.parse(readFileSync(deps.statePath, 'utf8')) as NonNullable<WalkthroughDeps['seed']>);
  const validated = async () => (await c.lcl()).index;
  const signers = {
    'lawyer-a': demoSigner(st.keys['lawyer-a'] as DemoKey, validated),
    observer: demoSigner(st.observer, validated),
  };
  return {
    async call(who, method, path, body) {
      const s = await signers[who].request('', method, path, body);
      const r = await app.inject({
        method,
        url: s.url,
        headers: s.init.headers as Record<string, string>,
        ...(s.init.body === undefined ? {} : { payload: s.init.body as string }),
      });
      if (r.statusCode !== 200) throw new Error(`${method} ${path} -> HTTP ${r.statusCode} ${r.body.slice(0, 200)}`);
      return r.json();
    },
  };
}
