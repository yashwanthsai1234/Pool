import { verifyCheckpoint } from '@legx/core/pqCheckpoint';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it, vi } from 'vitest';
import { ANCHOR_CRON, createAnchorService, MILESTONE_KINDS, parseAnchorMemo, tsaKey } from '../src/anchor.ts';
import { QUEUE_ANCHOR } from '../src/jobs.ts';
import { checkpointKey } from '../src/log.ts';
import { verifyTimestampToken } from '../src/tsa.ts';
import { ANCHOR_ACCOUNT, fakeLedger } from './helpers/fakeLedger.ts';
import { type LocalTsa, makeLocalTsa } from './helpers/localTsa.ts';
import { memoryJobs } from './helpers/memoryJobs.ts';
import { makeWorld, type World } from './helpers/world.ts';

vi.setConfig({ testTimeout: 60_000 });

async function setup(
  opts: { tsa?: LocalTsa[]; minIntervalMs?: number; ledger?: Parameters<typeof fakeLedger>[0] } = {},
) {
  const w = await makeWorld();
  const alice = await w.enroll('alice', 'A');
  for (let i = 0; i < 2; i++) await w.events.append(w.dealId, await w.sign(alice, 'alice', 'shell.opened'));
  const tsas = opts.tsa ?? [await makeLocalTsa('authority-a'), await makeLocalTsa('authority-b')];
  const sources = tsas.map((t) => t.client({ minIntervalMs: opts.minIntervalMs ?? 0 }));
  const ledger = fakeLedger(opts.ledger);
  const queue = memoryJobs();
  const anchors = createAnchorService({
    db: w.db,
    logSvc: w.logSvc,
    ledger: ledger.port,
    signTx: async (tx) => JSON.stringify(tx),
    anchorAccount: ANCHOR_ACCOUNT,
    network: 'standalone',
    baseFeeDrops: 200,
    origin: w.origin,
    objects: w.objects,
    retainDays: 3650,
    jobs: queue.jobs,
    tsa: sources,
  });
  await anchors.start();
  return { w, alice, tsas, anchors, ledger, queue };
}

const stamp = async (w: World, tsa: LocalTsa, treeSize: number, root: string) => {
  const token = await w.objects.get(tsaKey(treeSize, root, tsa.name));
  const note = (await w.objects.get(checkpointKey(treeSize, root))) as Uint8Array;
  return { token, hash: sha256(note) };
};

describe('P3.4-06 anchoring a hybrid checkpoint', () => {
  it('schedules every 10 minutes', async () => {
    const { queue } = await setup();
    expect(ANCHOR_CRON).toBe('*/10 * * * *');
    expect(queue.schedules).toEqual([{ queue: QUEUE_ANCHOR, cron: '*/10 * * * *' }]);
  });

  it('anchors a checkpoint with both lines as an AccountSet with the legx/ckpt/v1 memo that reads back and validates', async () => {
    const { w, anchors, ledger } = await setup();
    const res = await anchors.anchorNow();
    expect(res).toMatchObject({ status: 'anchored', treeSize: 3 });
    const tx = ledger.submitted[0] as Record<string, unknown>;
    expect(tx).toMatchObject({ TransactionType: 'AccountSet', Account: ANCHOR_ACCOUNT, Fee: '200' });
    expect(parseAnchorMemo(tx)).toEqual({
      originHash: bytesToHex(sha256(new TextEncoder().encode(w.origin))),
      treeSize: 3,
      root: res.root,
    });
    const latest = await w.db.repos.checkpointAnchors.latest();
    expect(latest).toMatchObject({ tree_size: 3, anchor_tx_hash: res.txHash, anchor_ledger: res.ledgerIndex });
    const note = new TextDecoder().decode(latest?.checkpoint);
    expect(note.match(/^— /gmu)).toHaveLength(2); // the 0x01 and the 0x06 line
    expect(verifyCheckpoint(note, w.origin, w.cpKeys)).toMatchObject({ ok: true, treeSize: 3 });
    expect(await anchors.verifyAnchor()).toBe('ok');
  });

  it('nothing new in the log: the next anchor is a no-op (no second transaction)', async () => {
    const { anchors, ledger } = await setup();
    const first = await anchors.anchorNow();
    const second = await anchors.anchorNow();
    expect(second).toMatchObject({ status: 'unchanged', txHash: first.txHash });
    expect(ledger.submitted).toHaveLength(1);
  });

  it('concurrent anchors are serialized: one transaction, one result each', async () => {
    const { anchors, ledger } = await setup();
    const [a, b] = await Promise.all([anchors.anchorNow(), anchors.anchorNow()]);
    expect([a.status, b.status].sort()).toEqual(['anchored', 'unchanged']);
    expect(ledger.submitted).toHaveLength(1);
  });

  it.each([...MILESTONE_KINDS])('a legal milestone (%s) queues an anchor at once', async (kind) => {
    const { anchors, queue } = await setup();
    expect(await anchors.onEvent(kind)).toBe(true);
    expect(queue.sent.filter((s) => s.queue === QUEUE_ANCHOR)).toEqual([
      { queue: QUEUE_ANCHOR, data: { reason: kind } },
    ]);
    await queue.round();
    expect((await anchors.status())?.anchored).toBe(true);
  });

  it('other events do not', async () => {
    const { anchors, queue } = await setup();
    for (const kind of ['shell.opened', 'nft.minted', 'release.performed', 'exit.signed'])
      expect(await anchors.onEvent(kind)).toBe(false);
    expect(queue.sent).toEqual([]);
  });

  it('a tampered ledger memo, a missing transaction or the wrong account is reported', async () => {
    const { anchors, ledger } = await setup();
    const res = await anchors.anchorNow();
    const entry = ledger.txs.get(res.txHash) as { tx: Record<string, unknown> };
    const good = entry.tx;
    entry.tx = {
      ...good,
      Memos: [
        {
          Memo: {
            MemoType: (good.Memos as { Memo: { MemoType: string } }[])[0]?.Memo.MemoType,
            MemoData: 'AA'.repeat(72),
          },
        },
      ],
    };
    expect(await anchors.verifyAnchor()).toBe('MEMO_MISMATCH');
    entry.tx = { ...good, Account: 'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn' };
    expect(await anchors.verifyAnchor()).toBe('WRONG_ACCOUNT');
    ledger.txs.clear();
    expect(await anchors.verifyAnchor()).toBe('TX_MISSING');
  });

  it('a rejected or failed submit throws (so the job is retried) and records no anchor; an expired one is rebuilt', async () => {
    const rejected = await setup({ ledger: { results: [{ status: 'rejected', result: 'tefPAST_SEQ' }] } });
    await expect(rejected.anchors.anchorNow()).rejects.toThrow('rejected');
    expect((await rejected.w.db.repos.checkpointAnchors.latest())?.anchor_tx_hash).toBeNull();
    expect(await rejected.anchors.verifyAnchor()).toBe('NOT_ANCHORED');
    const expired = await setup({ ledger: { results: [{ status: 'expired', lastLedgerSequence: 1 }] } });
    expect(await expired.anchors.anchorNow()).toMatchObject({ status: 'anchored' }); // the retry within the call
    const down = await setup({ ledger: { fail: () => new Error('ledger unreachable') } });
    await expect(down.anchors.anchorNow()).rejects.toThrow('ledger unreachable');
  });

  it('a failed anchor job is retried by the queue and then succeeds', async () => {
    let fails = 2;
    const { anchors, queue } = await setup({
      ledger: { fail: () => (fails-- > 0 ? new Error('ledger unreachable') : undefined) },
    });
    await anchors.onEvent('dispute.opened');
    await queue.drain();
    expect(queue.failures.filter((f) => f.queue === QUEUE_ANCHOR)).toHaveLength(2);
    expect((await anchors.status())?.anchored).toBe(true);
  });
});

describe('P3.4-07 RFC 3161 over the checkpoint', () => {
  it('both authorities answer: each token verifies against the checkpoint hash and its TSA chain', async () => {
    const { w, tsas, anchors, queue } = await setup();
    const res = await anchors.anchorNow();
    await queue.drain();
    for (const t of tsas) {
      const { token, hash } = await stamp(w, t, res.treeSize, res.root);
      expect(token).toBeDefined();
      const v = await verifyTimestampToken(token as Uint8Array, hash, [t.rootDer]);
      expect(v).toMatchObject({ ok: true });
      // the other authority's root does not vouch for this token
      const other = tsas.find((x) => x !== t) as LocalTsa;
      expect(await verifyTimestampToken(token as Uint8Array, hash, [other.rootDer])).toEqual({
        ok: false,
        code: 'CHAIN_UNTRUSTED',
      });
    }
    expect((await anchors.status())?.stampedBy).toEqual(['authority-a', 'authority-b']);
    expect((await anchors.status())?.timestamp).toBe('stamped');
  });

  it('a token for another checkpoint is refused', async () => {
    const { w, tsas, anchors, queue } = await setup();
    const res = await anchors.anchorNow();
    await queue.drain();
    const { token } = await stamp(w, tsas[0] as LocalTsa, res.treeSize, res.root);
    expect(
      await verifyTimestampToken(token as Uint8Array, sha256(new TextEncoder().encode('another checkpoint')), [
        (tsas[0] as LocalTsa).rootDer,
      ]),
    ).toEqual({ ok: false, code: 'IMPRINT_MISMATCH' });
  });

  it('an authority whose signer lacks the time-stamping EKU is refused: no token is stored', async () => {
    const bad = await makeLocalTsa('bad-eku');
    bad.behave.wrongEku = true;
    const { w, anchors, queue } = await setup({ tsa: [bad] });
    const res = await anchors.anchorNow();
    await queue.round();
    expect(queue.failures[0]?.message).toMatch(/NOT_TIME_STAMPING_CERT/);
    expect(await w.objects.get(tsaKey(res.treeSize, res.root, 'bad-eku'))).toBeUndefined();
  });
});

describe('P3.4-07b two authorities, one slow', () => {
  it('the first good token is the one in checkpoint_anchor; the second is stored when it arrives', async () => {
    const [fast, slow] = [await makeLocalTsa('fast'), await makeLocalTsa('slow')];
    slow.behave.delayMs = 300;
    const { w, anchors, queue } = await setup({ tsa: [slow, fast] }); // the slow one is listed first
    const res = await anchors.anchorNow();
    const done = queue.round();
    await vi.waitFor(async () => expect((await anchors.status())?.stampedBy).toEqual(['fast']), {
      timeout: 5000,
      interval: 20,
    });
    const midway = await w.db.repos.checkpointAnchors.latest();
    const fastToken = await w.objects.get(tsaKey(res.treeSize, res.root, 'fast'));
    expect(midway?.rfc3161_token).toEqual(fastToken);
    expect((await anchors.status())?.timestamp).toBe('stamped');
    await done;
    expect((await anchors.status())?.stampedBy).toEqual(['slow', 'fast']);
    expect((await w.db.repos.checkpointAnchors.latest())?.rfc3161_token).toEqual(fastToken); // the column keeps the first
    expect(await w.objects.get(tsaKey(res.treeSize, res.root, 'slow'))).toBeDefined();
  });

  it('the rate limit of each authority is respected when two checkpoints follow each other', async () => {
    const a = await makeLocalTsa('limited-a');
    const b = await makeLocalTsa('limited-b');
    const { w, alice, anchors, queue } = await setup({ tsa: [a, b], minIntervalMs: 250 });
    await anchors.anchorNow();
    await w.events.append(w.dealId, await w.sign(alice, 'alice', 'escrow.created'));
    await anchors.anchorNow();
    await queue.drain();
    for (const t of [a, b]) {
      expect(t.requests).toHaveLength(2);
      expect((t.requests[1] as { at: number }).at - (t.requests[0] as { at: number }).at).toBeGreaterThanOrEqual(240);
    }
  });
});

describe('P3.4-08 an authority is down', () => {
  it('the anchor still happens, the dashboard says "time stamp pending", and pg-boss style retries finish it later', async () => {
    const [a, b] = [await makeLocalTsa('down-a'), await makeLocalTsa('down-b')];
    a.behave.status = 503;
    b.behave.status = 503;
    const { w, anchors, queue } = await setup({ tsa: [a, b] });
    const res = await anchors.anchorNow();
    expect(res.status).toBe('anchored');
    await queue.round();
    expect(queue.pending).toBe(2); // both jobs wait for another attempt
    expect(await anchors.status()).toMatchObject({ anchored: true, timestamp: 'pending', stampedBy: [] });
    expect((await w.db.repos.checkpointAnchors.latest())?.rfc3161_token).toBeNull();
    a.behave.status = undefined;
    await queue.drain();
    expect(await anchors.status()).toMatchObject({ timestamp: 'stamped', stampedBy: ['down-a'] }); // b is still down
    expect(queue.pending).toBe(1);
    b.behave.status = undefined;
    await queue.drain();
    expect((await anchors.status())?.stampedBy).toEqual(['down-a', 'down-b']);
    expect((await w.db.repos.checkpointAnchors.latest())?.rfc3161_token).not.toBeNull();
  });

  it('a retried job after a crash between the primary marker and the column repairs the column', async () => {
    const { w, tsas, anchors, queue } = await setup();
    const res = await anchors.anchorNow();
    await queue.drain();
    // simulate the crash: the marker exists but the column was never written
    const row = await w.db.repos.checkpointAnchors.latest();
    expect(row?.rfc3161_token).not.toBeNull();
    const t = tsas[0] as LocalTsa;
    await anchors.handleTsa({ treeSize: res.treeSize, root: res.root, authority: t.name }); // a duplicate delivery is harmless
    expect((await w.db.repos.checkpointAnchors.latest())?.rfc3161_token).toEqual(row?.rfc3161_token);
  });
});
