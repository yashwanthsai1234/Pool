// P3.3-04 to P3.3-08 and the resume, revoke and enrollment-list tests, on the standalone ledger (6104) and Postgres 18 (5503).
import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { BarRegistryAdapter } from '@legx/contracts/ports';
import { openBarCommitment, verifyBarDealLink, verifyBarVerification } from '@legx/core/bar';
import type { Database } from '@legx/db';
import { startRegistry } from '@legx/mock-bar-registry';
import { advanceCloseTime, connect, fundAccount } from '@legx/xrpl';
import { ledgerPort } from '@legx/xrpl/submit';
import { bytesToHex } from '@noble/hashes/utils.js';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from 'xrpl';
import xrpl from 'xrpl';
import { closer } from '../../../packages/xrpl/test-int/support.ts';
import { demoAdapter, manualAdapter } from '../src/adapters.ts';
import { VerifierError } from '../src/errors.ts';
import { startOnboardingJobs } from '../src/jobs.ts';
import { createVerifier, type VerifierDeps } from '../src/service.ts';
import { verifierTrust } from '../src/signing.ts';
import { env, freshDb, newSigner } from './support.ts';

type Wallet = InstanceType<typeof xrpl.Wallet>;
const signWith = (w: Wallet) => async (tx: unknown) => w.sign(tx as never).tx_blob;
const hex = (s: string) => Buffer.from(s, 'utf8').toString('hex').toUpperCase();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let client: Client;
let ticker: Client;
let stop: () => Promise<void>;
let registry: Awaited<ReturnType<typeof startRegistry>>;
let db: Database;
let dbUrl: string;
let ledger: ReturnType<typeof ledgerPort>;
const logs: string[] = [];
const signer = newSigner();
let issuer: Wallet;
let deps: VerifierDeps;
const manual = manualAdapter();

beforeAll(async () => {
  client = await connect(env);
  ticker = await connect(env);
  stop = closer(ticker, 100);
  registry = await startRegistry(0);
  ({ db, url: dbUrl } = await freshDb());
  ledger = ledgerPort(client, env, { pollMs: 50, timeoutMs: 60_000 });
  issuer = await fundAccount(env, client);
  const demo = demoAdapter({
    baseUrl: `http://127.0.0.1:${(registry.address() as AddressInfo).port}`,
    jurisdictions: { XA: 'XA-DM' },
  });
  deps = {
    db,
    ledger,
    signer,
    issuer: { address: issuer.classicAddress, signer: { sign: signWith(issuer) } },
    adapters: new Map<string, BarRegistryAdapter>([
      ['XA', demo],
      ['XB', manual],
    ]),
    log: (event, fields) => logs.push(`${event} ${JSON.stringify(fields)}`),
  };
}, 120_000);
afterAll(async () => {
  await stop();
  await ticker.disconnect();
  await client.disconnect();
  await new Promise<void>((r) => registry.close(() => r()));
  await db.close();
});

const credentialsOf = async (ops: string) =>
  (await client.request({ command: 'account_objects', account: ops, type: 'credential', ledger_index: 'validated' }))
    .result.account_objects as unknown as Array<Record<string, unknown>>;

// An operations account that accepts when asked (the lawyer's console, in production).
const withAcceptor = (ops: Wallet, base: VerifierDeps = deps): VerifierDeps => ({
  ...base,
  opsAccept: async (tx) => ops.sign(tx as never).tx_blob,
});

async function newOps() {
  return await fundAccount(env, client, 100);
}

describe('P3.3-04 order: the operations account must exist first', () => {
  it('refuses before any ledger write, adapter call or signature', async () => {
    const ghost = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
    let lookups = 0;
    let submits = 0;
    const spyAdapter: BarRegistryAdapter = {
      name: 'spy',
      lookup: async () => {
        lookups++;
        throw new Error('must not be called');
      },
    };
    const v = createVerifier({
      ...deps,
      adapters: new Map([['XA', spyAdapter]]),
      ledger: {
        ...ledger,
        submitReliable: async (b) => {
          submits++;
          return ledger.submitReliable(b);
        },
      },
    });
    await expect(
      v.onboard({ opsAccount: ghost.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0001' }),
    ).rejects.toMatchObject({ code: 'OPS_ACCOUNT_MISSING' });
    expect({ lookups, submits }).toEqual({ lookups: 0, submits: 0 });
    expect(await db.repos.lawyers.get(ghost.classicAddress)).toBeUndefined();
  });
});

describe('P3.3-05 full onboarding', () => {
  it('leaves LEGX_ATTORNEY on the ledger accepted, with the right URI and expiry', async () => {
    const ops = await newOps();
    const v = createVerifier(withAcceptor(ops));
    const r = await v.onboard({ opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0001' });
    if (r.state !== 'complete') throw new Error('expected complete');

    const [cred] = await credentialsOf(ops.classicAddress);
    expect(cred).toMatchObject({
      LedgerEntryType: 'Credential',
      Issuer: issuer.classicAddress,
      Subject: ops.classicAddress,
      CredentialType: hex('LEGX_ATTORNEY'),
    });
    expect((cred?.Flags as number) & 0x00010000).toBe(0x00010000); // lsfAccepted
    expect(cred?.URI).toBe(hex(`legx:bar:v1:${r.verificationSha256.toUpperCase()}`));
    const stored = (await db.repos.barVerifications.listFor(ops.classicAddress))[0];
    expect(stored?.envelope_sha256).toBe(r.verificationSha256);
    const checkedAt = (await ledger.ledgerHeader(stored?.checked_at_ledger ?? 0)).closeTime;
    const exp = cred?.Expiration as number;
    expect(exp).toBe(r.expiration);
    expect(exp - 90 * 86400).toBeGreaterThanOrEqual(checkedAt);
    expect(exp - 90 * 86400).toBeLessThanOrEqual((await ledger.validatedLedger()).closeTime);

    // The record verifies as the gate will check it, and the rows and events are there.
    const now = (await ledger.validatedLedger()).closeTime;
    const checked = verifyBarVerification({
      envelopeBytes: stored?.envelope ?? new Uint8Array(),
      trust: await verifierTrust(signer),
      opsAccount: ops.classicAddress,
      checkedAtCloseTime: checkedAt,
      nowCloseTime: now,
    });
    expect(checked.ok).toBe(true);
    expect((await db.repos.attorneyCredentials.listFor(ops.classicAddress))[0]).toMatchObject({
      create_tx_hash: r.createTxHash,
      accept_tx_hash: r.acceptTxHash,
      expiration: exp,
    });
    const topics = (
      await pool().query("select topic from outbox where convert_from(payload,'UTF8') like $1", [
        `%${ops.classicAddress}%`,
      ])
    ).rows.map((x) => x.topic);
    expect(topics).toContain('bar.verified');
    expect(logs.some((l) => l.startsWith('verifier.signed') && l.includes('BarVerification'))).toBe(true);
  }, 120_000);

  it('is idempotent: a second run changes nothing', async () => {
    const ops = await newOps();
    const v = createVerifier(withAcceptor(ops));
    const i = { opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0002' };
    const a = await v.onboard(i);
    const b = await v.onboard(i);
    expect(b).toEqual(a);
    expect(await credentialsOf(ops.classicAddress)).toHaveLength(1);
    expect(await db.repos.barVerifications.listFor(ops.classicAddress)).toHaveLength(1);
    expect(await db.repos.attorneyCredentials.listFor(ops.classicAddress)).toHaveLength(1);
  }, 120_000);

  it('refuses a struck-off lawyer and issues nothing', async () => {
    const ops = await newOps();
    const v = createVerifier(withAcceptor(ops));
    await expect(
      v.onboard({ opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0003' }),
    ).rejects.toMatchObject({ code: 'NOT_ACTIVE' });
    await expect(
      v.onboard({ opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-9999' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(await credentialsOf(ops.classicAddress)).toHaveLength(0);
    expect(await db.repos.lawyers.get(ops.classicAddress)).toBeUndefined();
  }, 120_000);

  it('refuses the same operations account with another bar number', async () => {
    const ops = await newOps();
    const v = createVerifier(withAcceptor(ops));
    await v.onboard({ opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0001' });
    await expect(
      v.onboard({ opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0002' }),
    ).rejects.toMatchObject({ code: 'BAR_NUMBER_MISMATCH' });
  }, 120_000);

  it('an unknown jurisdiction and a broken registry give clean errors', async () => {
    const ops = await newOps();
    const broken: BarRegistryAdapter = { name: 'broken', lookup: () => new Promise(() => undefined) };
    const slow = demoAdapter({ baseUrl: 'http://127.0.0.1:1', timeoutMs: 200 });
    const v = createVerifier({
      ...deps,
      adapters: new Map([
        ['XA', slow],
        ['XC', { name: 'x', lookup: broken.lookup }],
      ]),
    });
    await expect(
      v.onboard({ opsAccount: ops.classicAddress, jurisdiction: 'XZ', barNumber: 'DEMO-0001' }),
    ).rejects.toMatchObject({ code: 'NO_ADAPTER' });
    await expect(
      v.onboard({ opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0001' }),
    ).rejects.toMatchObject({ code: 'ADAPTER_UNREACHABLE' });
    await expect(
      v.onboard({ opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: '../x' }),
    ).rejects.toBeInstanceOf(VerifierError);
    expect(await credentialsOf(ops.classicAddress)).toHaveLength(0);
  }, 120_000);
});

describe('resume after a crash at every step', () => {
  it('a signing failure on 0a, then a retry: one verification, one credential', async () => {
    const ops = await newOps();
    let failed = false;
    const flaky: VerifierDeps = {
      ...withAcceptor(ops),
      issuer: {
        address: issuer.classicAddress,
        signer: {
          sign: async (tx) => {
            if (!failed) {
              failed = true;
              throw new Error('kms down');
            }
            return signWith(issuer)(tx);
          },
        },
      },
    };
    const v = createVerifier(flaky);
    const i = { opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0001' };
    await expect(v.onboard(i)).rejects.toThrow('kms down');
    expect(await credentialsOf(ops.classicAddress)).toHaveLength(0);
    const r = await v.onboard(i);
    expect(r.state).toBe('complete');
    expect(await db.repos.barVerifications.listFor(ops.classicAddress)).toHaveLength(1);
    expect(await credentialsOf(ops.classicAddress)).toHaveLength(1);
  }, 120_000);

  it('the lawyer has not accepted yet: awaiting, then complete on the next run (0a is not repeated)', async () => {
    const ops = await newOps();
    const i = { opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0002' };
    const first = await createVerifier(deps).onboard(i);
    expect(first.state).toBe('awaiting_ops_accept');
    const [created] = await credentialsOf(ops.classicAddress);
    expect((created?.Flags as number) & 0x00010000).toBe(0);
    const second = await createVerifier(withAcceptor(ops)).onboard(i);
    expect(second.state).toBe('complete');
    expect(await credentialsOf(ops.classicAddress)).toHaveLength(1);
  }, 120_000);

  it('a crash after the accept validated but before the row: the next run finds both hashes on the ledger', async () => {
    const ops = await newOps();
    let failed = false;
    const repos = Object.create(db.repos) as typeof db.repos;
    const real = db.repos.attorneyCredentials;
    Object.defineProperty(repos, 'attorneyCredentials', {
      value: {
        listFor: real.listFor.bind(real),
        insert: async (...a: Parameters<typeof real.insert>) => {
          if (!failed) {
            failed = true;
            throw new Error('db down');
          }
          return real.insert(...a);
        },
      },
    });
    const i = { opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0001' };
    await expect(createVerifier({ ...withAcceptor(ops), db: { ...db, repos } as Database }).onboard(i)).rejects.toThrow(
      'db down',
    );
    const r = await createVerifier(withAcceptor(ops)).onboard(i);
    if (r.state !== 'complete') throw new Error('expected complete');
    const row = (await db.repos.attorneyCredentials.listFor(ops.classicAddress))[0];
    expect(row).toMatchObject({ create_tx_hash: r.createTxHash, accept_tx_hash: r.acceptTxHash });
    expect(r.createTxHash).not.toBe(r.acceptTxHash);
    const create = await client.request({ command: 'tx', transaction: r.createTxHash });
    expect(create.result.tx_json.TransactionType).toBe('CredentialCreate');
  }, 120_000);

  it('the pg-boss job retries until the lawyer accepts (job data holds no secret)', async () => {
    const ops = await newOps();
    let acceptReady = false;
    const v = createVerifier({
      ...deps,
      opsAccept: async (tx) => (acceptReady ? ops.sign(tx as never).tx_blob : undefined),
    });
    await v.verify({ opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0001' });
    const jobs = await startOnboardingJobs({
      connectionString: dbUrl,
      verifier: v,
      pollSeconds: 0.5,
      retryDelaySeconds: 1,
      retryLimit: 30,
    });
    try {
      await jobs.enqueue(ops.classicAddress);
      await sleep(3000);
      expect((await credentialsOf(ops.classicAddress))[0]?.Flags).toBe(0);
      acceptReady = true;
      let done = false;
      for (let n = 0; n < 60 && !done; n++) {
        await sleep(500);
        done = (((await credentialsOf(ops.classicAddress))[0]?.Flags as number) & 0x00010000) !== 0;
      }
      expect(done).toBe(true);
      const jobRows = await pool().query('select data from legx_verifier_jobs.job');
      expect(JSON.stringify(jobRows.rows)).not.toContain('DEMO-0001');
    } finally {
      await jobs.stop();
    }
  }, 120_000);
});

describe('P3.3-07, P3.3-08 the per-deal link', () => {
  it('opens LC with the salt, signs a BarDealLink the gate accepts, and forgets the salt', async () => {
    const ops = await newOps();
    const v = createVerifier(withAcceptor(ops));
    await v.onboard({ opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0001' });
    const salt = randomBytes(32);
    const saltCopy = Uint8Array.from(salt);
    const dealId = (
      await db.repos.deals.insert({
        state: 'DRAFT',
        network: 'standalone',
        contract_root: 'ab'.repeat(32),
        payout_a: ops.classicAddress,
        payout_b: ops.classicAddress,
        amount_drops: '1000000',
      })
    ).deal_id;
    const lawyerPub = ops.publicKey;
    const lc = bytesToHex(openBarCommitment(saltCopy, 'XA', 'DEMO-0001'));
    const bytes = await v.link({
      dealId,
      contractRoot: 'ab'.repeat(32),
      role: 'LA',
      lawyerPub,
      opsAccount: ops.classicAddress,
      barNumber: 'DEMO-0001',
      salt,
      barCommitment: lc,
    });
    expect(salt.every((b) => b === 0)).toBe(true);

    const verification = (await db.repos.barVerifications.listFor(ops.classicAddress))[0];
    const now = (await ledger.validatedLedger()).closeTime;
    const gate = verifyBarDealLink({
      linkBytes: bytes,
      verificationBytes: verification?.envelope ?? new Uint8Array(),
      trust: await verifierTrust(signer),
      sealed: {
        dealId,
        contractRoot: 'ab'.repeat(32),
        role: 'LA',
        lawyerPub,
        barCommitment: lc,
        opsAccount: ops.classicAddress,
      },
      checkedAtCloseTime: (await ledger.ledgerHeader(verification?.checked_at_ledger ?? 0)).closeTime,
      nowCloseTime: now,
    });
    expect(gate.ok).toBe(true);
    expect(await db.repos.barDealLinks.list(dealId)).toHaveLength(1);

    // A second request for the same deal and role returns the stored link without signing again.
    const again = await v.link({
      dealId,
      contractRoot: 'ab'.repeat(32),
      role: 'LA',
      lawyerPub,
      opsAccount: ops.classicAddress,
      barNumber: 'DEMO-0001',
      salt: Uint8Array.from(saltCopy),
      barCommitment: lc,
    });
    expect(again).toEqual(bytes);

    // P3.3-08: no table, no job row and no log line holds the salt or the bar number.
    const needles = [
      bytesToHex(saltCopy),
      Buffer.from(saltCopy).toString('base64'),
      Buffer.from(saltCopy).toString('base64url'),
      Buffer.from(saltCopy).toString('latin1'),
      'DEMO-0001',
      'demo-0001',
    ];
    const dump = await wholeDatabase();
    // The scan can see inside bytea columns and envelopes (it would find these), so a clean result means something.
    expect(dump).toContain('BarDealLink');
    expect(dump).toContain('"jurisdiction":"XA"');
    for (const n of needles) {
      expect(dump, `database holds ${n}`).not.toContain(n);
      expect(logs.join('\n'), `log holds ${n}`).not.toContain(n);
    }
  }, 120_000);

  it('refuses a wrong salt, a wrong bar number and a stale or unknown lawyer; the salt is zeroed anyway', async () => {
    const ops = await newOps();
    const v = createVerifier(withAcceptor(ops));
    const common = {
      dealId: crypto.randomUUID(),
      contractRoot: 'cd'.repeat(32),
      role: 'LB' as const,
      lawyerPub: ops.publicKey,
      opsAccount: ops.classicAddress,
    };
    const lc = (s: Uint8Array) => bytesToHex(openBarCommitment(s, 'XA', 'DEMO-0001'));
    const salt = randomBytes(32);
    const good = lc(salt);
    const salt1 = Uint8Array.from(salt);
    await expect(v.link({ ...common, barNumber: 'DEMO-0001', salt: salt1, barCommitment: good })).rejects.toMatchObject(
      { code: 'NOT_ONBOARDED' },
    );
    expect(salt1.every((b) => b === 0)).toBe(true);
    await v.onboard({ opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0001' });
    const salt2 = randomBytes(32);
    await expect(v.link({ ...common, barNumber: 'DEMO-0001', salt: salt2, barCommitment: good })).rejects.toMatchObject(
      { code: 'COMMITMENT_MISMATCH' },
    );
    expect(salt2.every((b) => b === 0)).toBe(true);
    await expect(
      v.link({ ...common, barNumber: 'DEMO-0002', salt: Uint8Array.from(salt), barCommitment: lc(salt) }),
    ).rejects.toMatchObject({ code: 'BAR_NUMBER_MISMATCH' });
    expect(await db.repos.barDealLinks.list(common.dealId)).toHaveLength(0);
  }, 120_000);
});

describe('P3.3-06 re-verification', () => {
  it('after the age limit: CredentialDelete, a new create and accept, a new link; a struck-off lawyer is revoked', async () => {
    const maxAgeSeconds = 12;
    const ops = await newOps();
    const ops2 = await newOps();
    const short = (o: Wallet): VerifierDeps => ({ ...withAcceptor(o), maxAgeSeconds });
    const v1 = createVerifier(short(ops));
    const v2 = createVerifier(short(ops2));
    const i1 = { opsAccount: ops.classicAddress, jurisdiction: 'XA', barNumber: 'DEMO-0001' };
    const i2 = { opsAccount: ops2.classicAddress, jurisdiction: 'XB', barNumber: 'ZZ-77' };
    manual.upload({
      jurisdiction: 'XB',
      barNumber: 'ZZ-77',
      status: 'active',
      page: new TextEncoder().encode('page v1'),
      url: 'https://registry.example/zz77',
    });
    const first = await v1.onboard(i1);
    await v2.onboard(i2);
    if (first.state !== 'complete') throw new Error('expected complete');
    const t0 = (await ledger.validatedLedger()).closeTime;

    // Fresh: a second onboarding does nothing new.
    expect(await v1.onboard(i1)).toEqual(first);

    await advanceCloseTime(client, t0 + maxAgeSeconds + 1);
    const link = {
      dealId: (
        await db.repos.deals.insert({
          state: 'DRAFT',
          network: 'standalone',
          contract_root: 'ef'.repeat(32),
          payout_a: ops.classicAddress,
          payout_b: ops.classicAddress,
          amount_drops: '1',
        })
      ).deal_id,
      contractRoot: 'ef'.repeat(32),
      role: 'LA' as const,
      lawyerPub: ops.publicKey,
      opsAccount: ops.classicAddress,
      barNumber: 'DEMO-0001',
    };
    const salt = randomBytes(32);
    const lc = bytesToHex(openBarCommitment(salt, 'XA', 'DEMO-0001'));
    await expect(v1.link({ ...link, salt: Uint8Array.from(salt), barCommitment: lc })).rejects.toMatchObject({
      code: 'VERIFICATION_STALE',
    });

    const second = await v1.reverify(i1);
    if (second.state !== 'complete') throw new Error('expected complete');
    expect(second.verificationSha256).not.toBe(first.verificationSha256);
    expect(second.createTxHash).not.toBe(first.createTxHash);
    const creds = await credentialsOf(ops.classicAddress);
    expect(creds).toHaveLength(1);
    expect(creds[0]?.URI).toBe(hex(`legx:bar:v1:${second.verificationSha256.toUpperCase()}`));
    expect((creds[0]?.Flags as number) & 0x00010000).toBe(0x00010000);
    const del = await client.request({
      command: 'account_tx',
      account: issuer.classicAddress,
      ledger_index_min: -1,
      ledger_index_max: -1,
      limit: 400,
    });
    expect(JSON.stringify(del.result.transactions)).toContain('CredentialDelete');
    expect(await db.repos.attorneyCredentials.listFor(ops.classicAddress)).toHaveLength(2);

    const bytes = await v1.link({ ...link, salt: Uint8Array.from(salt), barCommitment: lc });
    const verification = (await db.repos.barVerifications.listFor(ops.classicAddress))[0];
    expect(verification?.envelope_sha256).toBe(second.verificationSha256);
    const gate = verifyBarDealLink({
      linkBytes: bytes,
      verificationBytes: verification?.envelope ?? new Uint8Array(),
      trust: await verifierTrust(signer),
      sealed: {
        dealId: link.dealId,
        contractRoot: link.contractRoot,
        role: 'LA',
        lawyerPub: link.lawyerPub,
        barCommitment: lc,
        opsAccount: ops.classicAddress,
      },
      checkedAtCloseTime: (await ledger.ledgerHeader(verification?.checked_at_ledger ?? 0)).closeTime,
      nowCloseTime: (await ledger.validatedLedger()).closeTime,
    });
    expect(gate.ok).toBe(true);

    // The second lawyer was struck off in the meantime: re-verification deletes the credential and reports it.
    manual.upload({
      jurisdiction: 'XB',
      barNumber: 'ZZ-77',
      status: 'not_active',
      page: new TextEncoder().encode('page v2: struck off'),
      url: 'https://registry.example/zz77',
    });
    expect(await credentialsOf(ops2.classicAddress)).toHaveLength(1);
    await expect(v2.reverify(i2)).rejects.toMatchObject({ code: 'NOT_ACTIVE' });
    expect(await credentialsOf(ops2.classicAddress)).toHaveLength(0);
  }, 240_000);
});

// Every row of every table in the database and in the job schema, as text.
function pool() {
  poolInstance ??= new pg.Pool({ connectionString: dbUrl, max: 2 });
  return poolInstance;
}
let poolInstance: pg.Pool | undefined;
afterAll(async () => {
  await poolInstance?.end();
});

async function wholeDatabase(): Promise<string> {
  const tables = (
    await pool().query(
      "select table_schema s, table_name t from information_schema.tables where table_schema in ('public','legx_verifier_jobs') and table_type='BASE TABLE'",
    )
  ).rows;
  const out: string[] = [];
  for (const { s, t } of tables) {
    const rows = await pool().query(`select row_to_json(x)::text as j from ${s}.${t} x`);
    out.push(...rows.rows.map((r) => r.j));
  }
  return expand(out.join('\n'));
}

// bytea columns come out as `\\x<hex>` and envelopes carry a base64 payload: decode both so a needle cannot hide in them.
function expand(text: string): string {
  const decoded = [...text.matchAll(/\\\\x([0-9a-f]+)/g)].map((m) => Buffer.from(m[1] ?? '', 'hex').toString('latin1'));
  const payloads = decoded.flatMap((d) =>
    [...d.matchAll(/"payload":"([A-Za-z0-9+/=]+)"/g)].map((m) => Buffer.from(m[1] ?? '', 'base64').toString('latin1')),
  );
  return [text, ...decoded, ...payloads].join('\n');
}
