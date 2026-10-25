// events.append: idempotency, chain position, who may post what, and refusals that leave nothing behind.
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { account, joinAll, ok } from './support/lifecycle.ts';
import {
  addTx,
  append,
  call,
  holderOf,
  makeEvent,
  makeWorld,
  newDeal,
  OPS_A,
  post,
  rndHex,
  SHELL,
  type World,
} from './support/world.ts';

vi.setConfig({ testTimeout: 180_000 });
let w: World;
let id: string;
beforeAll(async () => {
  w = await makeWorld();
  id = await newDeal(w);
  await joinAll(w, id);
});
afterAll(async () => w.close());

const count = async () => (await w.db.repos.evidenceEvents.listAfter(id, -1)).length;
const shellOpened = () => ({ wallet_address: SHELL, funding_tx_hash: addTx(w, 'Payment', account(w, 'alice')) });

describe('events.append', () => {
  it('a retry of the same bytes returns the first result and stores nothing new; a stale seq gets the current head', async () => {
    const n0 = await count();
    const b64 = await makeEvent(w, id, 'alice', 'shell.opened', shellOpened());
    const first = ok(await append(w, id, 'alice', b64));
    expect(first).toMatchObject({ status: 'stored', seq: n0, state: 'SHELL_OPEN' });
    const retry = ok(await append(w, id, 'alice', b64));
    expect(retry).toEqual(first);
    expect(await count()).toBe(n0 + 1);
    // Another event claiming the same seq (a race lost): the client learns the head and signs again.
    const stale = await makeEvent(
      w,
      id,
      'bob',
      'dispute.opened',
      { notice_sha256: rndHex(32) },
      { seq: n0, prevHash: '00'.repeat(32) },
    );
    const r = ok(await append(w, id, 'bob', stale));
    expect(r.status).toBe('seq_taken');
    expect(r.head).toEqual({ nextSeq: n0 + 1, prevHash: first.leafHash });
    const head = ok(await call(w, holderOf(w, 'bob'), 'GET', `/deals/${id}/events/head`));
    expect(head).toEqual(r.head);
  });

  it('refuses a wrong actor, a wrong signer, a role that may not post the kind, and a kind no party writes', async () => {
    const claim = await makeEvent(
      w,
      id,
      'alice',
      'dispute.opened',
      { notice_sha256: rndHex(32) },
      { actorRole: 'lawyerA' },
    );
    expect((await append(w, id, 'alice', claim)).status).toBe(403);
    // Signed by bob's keys but sent in alice's session.
    const bobSigned = await makeEvent(
      w,
      id,
      'bob',
      'dispute.opened',
      { notice_sha256: rndHex(32) },
      { actorRole: 'alice', holder: holderOf(w, 'bob') },
    );
    const r1 = await append(w, id, 'alice', bobSigned);
    expect(r1.status).toBe(403);
    expect(r1.body.error).toBe('actor_mismatch');
    const r2 = await post(w, id, 'bob', 'nft.minted', {
      nftoken_id: rndHex(32).toUpperCase(),
      mint_tx_hash: addTx(w, 'NFTokenMint', OPS_A),
      minter: OPS_A,
      signed_contract_seal: rndHex(32),
    });
    expect(r2.body.error).toBe('role_not_allowed');
    for (const kind of ['bar.verified', 'exit.validated', 'checkpoint.anchored', 'exit.signed']) {
      const r = await append(w, id, 'lawyerB', await makeEvent(w, id, 'lawyerB', kind, {}));
      expect([400, 403]).toContain(r.status);
    }
    const r3 = await append(
      w,
      id,
      'lawyerB',
      await makeEvent(w, id, 'lawyerB', 'bar.verified', { ops_account: SHELL, verification_sha256: rndHex(32) }),
    );
    expect(r3.body.error).toBe('kind_not_allowed');
  });

  it('the old lawyer B logs the release-code handover (OD-28); no other role may (I-W-6)', async () => {
    const data = { from_key_id: 'key-from', to_key_id: 'key-to', box_sha256: rndHex(32) };
    const r = await post(w, id, 'alice', 'release_code.handed_over', data);
    expect(r.body.error).toBe('role_not_allowed');
    const good = await append(w, id, 'lawyerB', await makeEvent(w, id, 'lawyerB', 'release_code.handed_over', data));
    expect(good.status).toBe(200);
    expect(ok(good).status).toBe('stored');
  });

  it('refuses a bad signature, a ledger transaction that is not validated or of the wrong type, and an illegal transition; nothing is stored', async () => {
    const n = await count();
    const good = await makeEvent(w, id, 'lawyerB', 'dispute.opened', { notice_sha256: rndHex(32) });
    const env = JSON.parse(Buffer.from(good, 'base64').toString());
    env.payload = Buffer.from(
      Buffer.from(env.payload, 'base64').toString().replace('dispute.opened', 'dispute.openeX'),
    ).toString('base64');
    const r1 = await append(w, id, 'lawyerB', Buffer.from(JSON.stringify(env)).toString('base64'));
    expect(r1.body.error).toBe('bad_event_signature');
    const r2 = await post(w, id, 'alice', 'shell.opened', {
      wallet_address: SHELL,
      funding_tx_hash: rndHex(32).toUpperCase(),
    });
    expect(r2.body.error).toBe('ledger_tx_not_validated');
    const r3 = await post(w, id, 'alice', 'shell.opened', {
      wallet_address: SHELL,
      funding_tx_hash: addTx(w, 'OfferCreate', 'rX'),
    });
    expect(r3.body.error).toBe('ledger_tx_wrong_type');
    const r4 = await post(w, id, 'alice', 'shell.opened', {
      wallet_address: SHELL,
      funding_tx_hash: addTx(w, 'Payment', 'rX', {}, 'tecUNFUNDED_PAYMENT'),
    });
    expect(r4.body.error).toBe('ledger_tx_failed');
    // OPEN_SHELL again: the deal is already SHELL_OPEN.
    const r5 = await post(w, id, 'alice', 'shell.opened', shellOpened());
    expect(r5.status).toBe(422);
    expect(r5.body.error).toBe('refused_illegal');
    expect(await count()).toBe(n);
  });

  it('events.list pages by seq and returns the stored bytes unchanged', async () => {
    const all = ok(await call(w, holderOf(w, 'bob'), 'GET', `/deals/${id}/events?afterSeq=-1&limit=500`));
    const stored = await w.db.repos.evidenceEvents.listAfter(id, -1);
    expect(all.events.map((e: { seq: number }) => e.seq)).toEqual(stored.map((e) => e.seq));
    expect(
      all.events.every((e: { envelope: string }, i: number) =>
        Buffer.from(e.envelope, 'base64').equals(Buffer.from(stored[i]?.envelope as Uint8Array)),
      ),
    ).toBe(true);
    const page = ok(await call(w, holderOf(w, 'bob'), 'GET', `/deals/${id}/events?afterSeq=3&limit=2`));
    expect(page.events.map((e: { seq: number }) => e.seq)).toEqual([4, 5]);
  });
});
