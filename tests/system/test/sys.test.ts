// SYS-* of IMPLEMENTATION Phase 6, against the composed server process (demo profile) and a real standalone ledger.
// A SYS flow that cannot run because a capability is missing is an `it.fails` over its prerequisite probes
// (support/probes.ts): it flips when the blockers are fixed. Flows that need a lawyer-side or party-side UI are pinned
// the same way until I-31 is fixed.
import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bytesToHex } from '@noble/curves/utils.js';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { run as verifyBundle } from '../../../tools/verifier-cli/src/cli.ts';
import { createDeal, type Deal } from '../support/deal.ts';
import { OWNER, type Probe, runProbe } from '../support/probes.ts';
import {
  containersUp,
  LEDGER_CONTAINER,
  makeHolder,
  PG_CONTAINER,
  type Stack,
  startStack,
  waitFor,
} from '../support/stack.ts';

let stack: Stack;
let deal: Deal;
const made: Deal[] = [];

beforeAll(async () => {
  if (!containersUp())
    throw new Error(
      `start ${PG_CONTAINER} and ${LEDGER_CONTAINER} first (LEGX_SYS_PG, LEGX_SYS_LEDGER, LEGX_SYS_*_CONTAINER)`,
    );
  stack = await startStack();
  deal = await createDeal(stack);
  made.push(deal);
}, 240_000);
afterAll(async () => {
  await stack?.stop();
});

const sql = async <T extends object>(text: string, params: unknown[] = []) => {
  const c = new pg.Client({ connectionString: stack.pgUrl });
  await c.connect();
  try {
    return (await c.query(text, params)).rows as T[];
  } finally {
    await c.end();
  }
};

async function needs(probes: Probe[]) {
  const failing: string[] = [];
  for (const p of probes) if (!(await runProbe(p, stack, deal))) failing.push(`${p} (${OWNER[p]})`);
  expect(failing, 'blocked by').toEqual([]);
}

// ---------------------------------------------------------------------------------------------------------------
// 6.1 Full flows. Prerequisite pins: the flow cannot be driven until every listed capability exists (see REGRESSION.md).
const FLOWS: [string, string, Probe[]][] = [
  [
    'SYS-01',
    'happy path P0 to P8 through the UI only',
    ['webWiring', 'keysRegister', 'purposes', 'gate', 'watcher', 'observer'],
  ],
  ['SYS-02', 'refund path', ['webWiring', 'keysRegister', 'watcher']],
  ['SYS-03', 'expiry: EscrowCancel after CancelAfter', ['watcher', 'webWiring', 'keysRegister']],
  ['SYS-04', 'dispute: award to Alice, 4-of-4 exit', ['webWiring', 'keysRegister', 'purposes']],
  ['SYS-05', 'lawyer B replaced before release', ['purposes', 'keysRegister', 'gate']],
  ['SYS-06', 'passport check fails then passes', ['gate', 'webWiring', 'zkRoute']],
  ['SYS-07', 'a party refuses the passport check or the seal update', ['gate', 'webWiring', 'purposes']],
  ['SYS-08', 'phone lost, recovery, refresh', ['recoveryProof', 'webWiring', 'keysRegister']],
  ['SYS-09', 'full flow with zero-knowledge proofs', ['zkRoute', 'webWiring', 'gate']],
  ['SYS-10', 'chip fallback under zk-or-chip', ['zkRoute', 'gate', 'webWiring']],
  ['SYS-12', 'partner leaves the firm: share refresh', ['recoveryProof', 'purposes']],
];
describe('SYS-0x full flows (prerequisite pins)', () => {
  // SYS-11 has no blocker left (release gate and zk.verify are composed): its prerequisite probes pass. The flow itself
  // (a stale presenceMsg refused at the gate) needs the party and lawyer UIs to be driven end to end: see REGRESSION.md.
  it('SYS-11 release blocked by a stale presenceMsg: prerequisites present (gate, zk.verify)', async () => {
    await needs(['gate', 'zkRoute']);
  }, 120_000);
  for (const [id, title, probes] of FLOWS)
    it.fails(`${id} ${title}: blocked by ${probes.map((p) => OWNER[p]).join(', ')}`, async () => {
      await needs(probes);
    }, 120_000);
});

// Flows whose whole check is one of the demo-profile attack scenes (apps/server demo-attacks, real ledger, real libraries).
const SCENES: [string, string, string][] = [
  ['SYS-A1', 'stranger-finish', 'tecNO_PERMISSION'],
  ['SYS-A2', 'master-key-on', ''],
  ['SYS-A3', 'double-exit', ''],
  ['SYS-A4', 'bundle-byte', ''],
  ['SYS-A5', 'fake-passport', ''],
  ['SYS-A6', 'stale-bar', ''],
  ['SYS-A9', 'stripped-pq', ''],
  ['SYS-A10', 'replayed-zk', ''],
  ['SYS-A11', 'foreign-share', ''],
];
describe('SYS-A attack scenes on the running server', () => {
  for (const [id, scene, code] of SCENES)
    it(`${id} ${scene} is defeated`, async () => {
      const res = await fetch(`${stack.url}/demo/attack/${scene}`, { method: 'POST' });
      const body = (await res.json()) as { defeated?: boolean; code?: string; detail?: string };
      expect(res.status, JSON.stringify(body)).toBe(200);
      expect(body.defeated, JSON.stringify(body)).toBe(true);
      if (code) expect(body.code).toBe(code);
    }, 180_000);
  it('SYS-13 a hybrid envelope without its ML-DSA signature is refused (the stripped-pq scene names the check)', async () => {
    const body = (await (await fetch(`${stack.url}/demo/attack/stripped-pq`, { method: 'POST' })).json()) as {
      code: string;
      defeated: boolean;
    };
    expect(body.defeated).toBe(true);
    expect(body.code).toMatch(/PQ|CROSS_SIG_MISSING/);
  }, 120_000);
});

describe('SYS-A8 another client opens Alice records', () => {
  it('a key pinned in another deal is refused', async () => {
    const other = await createDeal(stack);
    made.push(other);
    const mine = await stack.call(deal.alice, 'POST', `/deals/${deal.dealId}/records`, { side: 'A' });
    expect(mine.status, JSON.stringify(mine.body)).toBe(200);
    const theirs = await stack.call(other.alice, 'POST', `/deals/${deal.dealId}/records`, { side: 'A' });
    expect([401, 403]).toContain(theirs.status);
  });
  it('an unsigned request is refused before its body is read', async () => {
    const res = await fetch(`${stack.url}/deals/${deal.dealId}/records`, {
      method: 'POST',
      body: '{"side":"A"}',
      headers: { 'content-type': 'application/json' },
    });
    expect(res.status).toBe(401);
  });
  it('a replayed signed request is refused (single-use nonce, OD-5)', async () => {
    const s = await stack.signed(deal.alice, 'GET', `/deals/${deal.dealId}`);
    expect((await fetch(s.url, s.init)).status).toBe(200);
    expect((await fetch(s.url, s.init)).status).toBe(401);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// 6.3 Resilience
describe('SYS-R resilience', () => {
  it('SYS-R1 kill -9 the server and restart: the deal resumes, no event is lost or doubled, the feed has no gap', async () => {
    const before = await sql<{ seq: number }>('select seq from evidence_event where deal_id = $1 order by seq', [
      deal.dealId,
    ]);
    const feedBefore = await stack.feed(deal.alice, deal.dealId);
    await waitFor(() => feedBefore.messages.some((m) => m.type === 'row'), 10_000, 'rows');
    feedBefore.close();
    await stack.restart(true);
    const after = await stack.call(deal.alice, 'GET', `/deals/${deal.dealId}`);
    expect(after.status, JSON.stringify(after.body)).toBe(200);
    expect(after.body.state).toBe('DRAFT');
    const rows = await sql<{ seq: number }>('select seq from evidence_event where deal_id = $1 order by seq', [
      deal.dealId,
    ]);
    expect(rows).toEqual(before);
    const feed = await stack.feed(deal.alice, deal.dealId);
    await waitFor(() => feed.messages.filter((m) => m.type === 'row').length >= before.length, 10_000, 'replay');
    const seqs = feed.messages.filter((m) => m.type === 'row').map((m) => m.seq);
    expect(seqs).toEqual([...seqs].sort((a, b) => a - b));
    expect(new Set(seqs).size).toBe(seqs.length);
    feed.close();
  }, 180_000);

  it('SYS-R1b the keys that signed events before a kill still exist after it (I-W-12: the demo composition keeps its service and checkpoint keys in files)', async () => {
    const d = await createDeal(stack);
    made.push(d);
    const before = await sql<{ envelope: Buffer }>(
      'select envelope from evidence_event where deal_id = $1 and seq = 0',
      [d.dealId],
    );
    const serverKey = (b: Buffer) =>
      (JSON.parse(b.toString()) as { signatures: { keyid: string; sig: string }[] }).signatures[0]?.keyid;
    expect(serverKey((before[0] as { envelope: Buffer }).envelope)).toBeDefined();
    const demo = readFileSync(join(import.meta.dirname, '../../../apps/server/src/demo.ts'), 'utf8');
    expect(demo, 'random keys at start').not.toMatch(/generateNode(Signer|Checkpoint)Keys\(/);
  });

  it('SYS-R2 the ledger stops answering for 10 s: the server stays up, the validated index moves again afterwards', async () => {
    const feed = await stack.feed(deal.alice, deal.dealId);
    await waitFor(() => feed.messages.some((m) => m.type === 'ledger'), 10_000, 'first ledger push');
    spawnSync('docker', ['pause', LEDGER_CONTAINER]);
    await new Promise((r) => setTimeout(r, 10_000));
    spawnSync('docker', ['unpause', LEDGER_CONTAINER]);
    const mark = feed.messages.length;
    await waitFor(
      () => feed.messages.slice(mark).some((m) => m.type === 'ledger'),
      40_000,
      'a ledger push after the pause',
    );
    const health = (await (await fetch(`${stack.url}/health`)).json()) as { ports: Record<string, { status: string }> };
    expect(health.ports.ledger?.status).toBe('ok');
    expect(health.ports.watcher?.status).toBe('ok');
    feed.close();
  }, 120_000);

  it.todo('SYS-R3 a phone offline during signature collection: needs the party app wiring (I-31)');
  it.fails('SYS-R4 two lawyers press release at once: one EscrowFinish is built (blocked by I-14: escrow_finish is 501)', async () => {
    const [a, b] = await Promise.all(
      [deal.alice, deal.alice].map((h) =>
        stack.call(h, 'POST', `/deals/${deal.dealId}/signature-requests`, { purpose: 'escrow_finish' }),
      ),
    );
    expect([a?.status, b?.status]).toEqual([200, 200]);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// 6.4 Invariant monitor and privacy scan: they run after the tests above, over everything the system recorded.
describe('SYS-I monitors', () => {
  it('SYS-I1 every deal log is a gap-free hash chain, every outbox row sequence is gap-free', async () => {
    for (const d of made) {
      const ev = await sql<{ seq: number; prev_hash: Buffer; leaf_hash: Buffer }>(
        'select seq, prev_hash, leaf_hash from evidence_event where deal_id = $1 order by seq',
        [d.dealId],
      );
      ev.forEach((e, i) => {
        expect(Number(e.seq)).toBe(i);
        if (i > 0) expect(bytesToHex(e.prev_hash)).toBe(bytesToHex((ev[i - 1] as { leaf_hash: Buffer }).leaf_hash));
      });
      const ob = await sql<{ seq: number }>(
        'select seq from outbox where deal_id = $1 and seq is not null order by seq',
        [d.dealId],
      );
      ob.forEach((o, i) => {
        expect(Number(o.seq)).toBe(i);
      });
    }
  });

  it('SYS-I2 no key material, MRZ text or salt is in Postgres, the data folder or the server log', async () => {
    const secrets = made.flatMap((d) => [d.alice, d.lawyerA]).concat(stack.lawyer);
    // The first 32 bytes of an ML-DSA secret key are rho, which is also in the public key: take the secret part (K, s1).
    const needles = secrets.flatMap((h) => [
      bytesToHex(h.edSecret),
      bytesToHex(h.pqSecret.slice(32, 64)),
      Buffer.from(h.pqSecret.slice(33, 63)).toString('base64'),
    ]);
    const dbName = new URL(stack.pgUrl).pathname.slice(1);
    const dump = spawnSync('docker', ['exec', PG_CONTAINER, 'pg_dump', '-U', 'postgres', '--data-only', dbName], {
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
    }).stdout;
    expect(dump.length).toBeGreaterThan(1000);
    const files: string[] = [];
    const walk = (p: string) => {
      for (const n of readdirSync(p)) {
        const f = join(p, n);
        if (statSync(f).isDirectory()) walk(f);
        else files.push(f);
      }
    };
    walk(stack.dataDir);
    const haystacks = [dump, stack.logs(), ...files.map((f) => readFileSync(f).toString('latin1'))];
    for (const h of haystacks) {
      for (const n of needles) expect(h.includes(n), 'a secret key leaked').toBe(false);
      expect(h).not.toMatch(/P<[A-Z]{3}[A-Z<]{30,}/); // an MRZ line
      expect(h).not.toMatch(/zkSalt32|zk_salt/i);
    }
  }, 120_000);

  it.todo(
    'SYS-I3 every bundle of SYS-01 to 17 verifies offline: no flow can produce a bundle yet (records.bundle is 501, I-W-8)',
  );
  it('SYS-I3a records.bundle returns a bundle that tools/verifier-cli accepts (I-W-8)', async () => {
    const res = await stack.call(deal.alice, 'POST', `/deals/${deal.dealId}/bundle`, { side: 'A' });
    expect(res.status, `${JSON.stringify(res.body)}\n${stack.logs().slice(-1500)}`).toBe(200);
    const bytes = new Uint8Array(Buffer.from(res.body.zip as string, 'base64'));
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(res.body.sha256);
    const dir = mkdtempSync(join(tmpdir(), 'legx-sys-bundle-'));
    const path = join(dir, 'bundle.zip');
    writeFileSync(path, bytes);
    // The arbitrator pins the service key out of band; the test takes it from the key file the demo service wrote.
    const keys = JSON.parse(readFileSync(join(stack.dataDir, 'service-keys.json'), 'utf8')) as {
      ed25519: { pkcs8Pem: string };
    };
    const pin = bytesToHex(
      new Uint8Array(createPublicKey(keys.ed25519.pkcs8Pem).export({ format: 'der', type: 'spki' }).subarray(-32)),
    );
    const out: string[] = [];
    // Time stamps need the public authorities (not reachable from every test machine): they are a warning when absent.
    const code = await verifyBundle([path, '--out-dir', dir, '--profile', 'demo', '--service-key', pin], {
      out: (t) => out.push(t),
      err: (t) => out.push(t),
    });
    const report = JSON.parse(readFileSync(join(dir, 'legx-verify-report.json'), 'utf8')) as {
      findings: { check: string; status: string; message: string }[];
    };
    const failed = report.findings.filter((f) => f.status === 'fail');
    // Until keys.register is served (I-W-1), `stack.pin` writes the two `enrollment.pinned` events with a signer that is
    // not in the deal's key registry, so the arbitrator rightly refuses exactly those two events and nothing else.
    expect(
      failed.map((f) => `${f.check} ${f.file} ${f.message}`),
      out.join(''),
    ).toEqual([
      'hybrid-signature events/000001.dsse.json signature check failed: KEY_UNKNOWN',
      'hybrid-signature events/000002.dsse.json signature check failed: KEY_UNKNOWN',
    ]);
    expect(code).toBe(1);
  }, 120_000);
});

// ---------------------------------------------------------------------------------------------------------------
// Attacks and rules that are tested at package level and have no system-level path yet.
describe('SYS-14 to 17 and SYS-A7, A12 to A16', () => {
  for (const id of [
    'SYS-14 FROST nonce reuse at the relay',
    'SYS-15 recovery agent alone',
    'SYS-16 recovery cancel at hour 40',
    'SYS-17 stolen-share rotation',
    'SYS-A7 false payout address',
    'SYS-A12 swapped enrollment key',
    'SYS-A13 firm HSM without approval',
    'SYS-A14 copied chip data',
    'SYS-A15 devMode proof in production',
    'SYS-A16 checkpoint without the 0x06 line',
  ])
    it.todo(`${id}: package-level tests exist (see REGRESSION.md); a system path needs I-31 / I-14 / I-W-1`);
});
void makeHolder;
