// I-31 the real party services, on Chromium and WebKit: a real vault frame (over a MessageChannel), the typed client
// over MSW, and the pinned hybrid registry. Nothing is injected except the network and the public XRPL node.
import { ApiAuth } from '@legx/contracts/api';
import { bytesToHex, dealSeal, sha256, utf8ToBytes } from '@legx/core/dealcore';
import { type ChainEntry, leafHashOf, ZERO } from '@legx/core/evidence';
import { slotAddress, slotPubkey } from '@legx/core/frost';
import { signHybrid } from '@legx/core/hybridEnvelope';
import { toBase64 } from '@legx/core/pq';
import { connectVault, createVault, serveVault, vaultFrameHost } from '@legx/vault';
import { pqKeys } from '@legx/vault/pq/keys';
import { HttpResponse, http } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { copy, dealId, fakePrf, freshDb, makeSlot, sealedDeal } from '../../../../packages/vault/test/helpers.ts';
import { createApiClient } from '../../src/lib/api.ts';
import { startMocks } from '../../src/mocks/browser.ts';
import { examplesOf } from '../../src/mocks/examples.ts';
import { type RecordedRequest, restHandlers } from '../../src/mocks/handlers.ts';
import { runLockSequence } from '../../src/routes/party/-lock.ts';
import { createPartyServices } from '../../src/routes/party/-services.ts';

let worker: Awaited<ReturnType<typeof startMocks>>;
beforeAll(async () => {
  worker = await startMocks();
});
afterEach(() => worker.resetHandlers());
afterAll(() => worker.stop());

const EVENT = 'application/vnd.legx.event+json;v=1';
const PAIR = 'pair-lawyer';

async function world() {
  const id = dealId();
  const dbName = freshDb();
  const { port1, port2 } = new MessageChannel();
  serveVault(
    port2,
    createVault({ role: 'alice', dbName, deals: () => Promise.reject(new Error('no seal')) }),
    vaultFrameHost({ role: 'alice', dbName }),
  );
  const vault = connectVault(port1);
  await vault.enroll(id);
  const seen: RecordedRequest[] = [];
  // the lawyer's key, the one that signed the records
  const lawyerKeys = pqKeys({ role: 'lawyerA', dbName: freshDb() });
  await lawyerKeys.create(id);
  const signer = await lawyerKeys.hybridSigner(id, PAIR);
  const pub = await signer.publicKeys();
  const row = {
    key_id: PAIR,
    slot: 'LA',
    holder_role: 'console',
    ed25519_pub: bytesToHex(pub.ed25519),
    mldsa65_pub: toBase64(pub.mlDsa65),
    valid_from: 1000,
  };
  const entry = async (seq: number, prev: string, tamper = false): Promise<ChainEntry> => {
    const statement = { predicate: { seq, prev_hash: prev, sig_algs: ['ed25519', 'ml-dsa-65'], kind: 'x' } };
    const env = await signHybrid(EVENT, utf8ToBytes(JSON.stringify(statement)), signer);
    if (tamper)
      env.payload = toBase64(utf8ToBytes(JSON.stringify({ predicate: { ...statement.predicate, kind: 'y' } })));
    const envelopeBytes = utf8ToBytes(JSON.stringify(env));
    return { envelopeBytes, leafHash: leafHashOf(envelopeBytes) };
  };
  const rpcCalls: string[] = [];
  const services = (over: { txIndex?: number; role?: 'alice' | 'bob' } = {}) =>
    createPartyServices({
      dealId: id,
      role: over.role ?? 'alice',
      api: createApiClient({
        signRequest: (req) => vault.signApi({ dealId: id, pairId: 'pair-phone', ...req, ledgerIndex: 1236000 }),
      }),
      vault,
      closeTime: () => 2000,
      txLedgerIndex: async (h) => {
        rpcCalls.push(h);
        return over.txIndex;
      },
      validatedIndex: async () => 1236000,
    });
  const handlers = (responses: Record<string, unknown> = {}) =>
    worker.use(
      ...restHandlers({
        onRequest: (r) => seen.push(r),
        responses: { 'keys.get': row, ...responses },
      }),
    );
  return { id, vault, seen, entry, services, handlers, rpcCalls, sha256 };
}

describe('I-31 requests are signed inside the vault frame', () => {
  it('every call carries an ApiAuth the frame signed, over the path the server receives', async () => {
    const w = await world();
    w.handlers({
      'ledger.accountInfo': { exists: true, ledgerIndex: 5, flags: 0x00020000, sequence: 3, balanceDrops: '10' },
    });
    const s = w.services();
    expect(await s.accountInfo('rHhr2iRBgp3ZzzNH4YGQ59G7VAiGPEWj7f')).toEqual({ flags: 0x00020000 });
    const [req] = w.seen;
    expect(req?.path).toBe('/api/ledger/accounts/rHhr2iRBgp3ZzzNH4YGQ59G7VAiGPEWj7f');
    const auth = ApiAuth.parse(req?.auth);
    expect(auth.ledgerIndex).toBe(1236000);
    expect(auth.signatures.map((x) => x.keyid)).toEqual(['pair-phone#ed25519', 'pair-phone#ml-dsa-65']);
  });

  it('an account that does not exist is undefined, not a zero-flag account', async () => {
    const w = await world();
    w.handlers({ 'ledger.accountInfo': { exists: false, ledgerIndex: 5 } });
    expect(await w.services().accountInfo('rHhr2iRBgp3ZzzNH4YGQ59G7VAiGPEWj7f')).toBeUndefined();
  });
});

describe('I-31 records use the pinned hybrid registry', () => {
  it('a hybrid-signed chain passes; a tampered payload, an unknown key and a missing registry row fail', async () => {
    const w = await world();
    w.handlers();
    const s = w.services();
    const good = await w.entry(0, ZERO);
    const bad = await w.entry(1, good.leafHash, true);
    await s.prepareEnvelopes?.([good, bad]);
    const { entryLink } = await import('@legx/core/evidence');
    expect(s.checkEnvelope((entryLink(good) as unknown as { env: never }).env)).toBe(true);
    expect(s.checkEnvelope((entryLink(bad) as unknown as { env: never }).env)).toBe(false);
    const unknown = { ...(entryLink(good) as { env: { signatures: { keyid: string; sig: string }[] } }).env };
    expect(
      s.checkEnvelope({
        ...unknown,
        signatures: unknown.signatures.map((x) => ({ ...x, keyid: `other${x.keyid}` })),
      } as never),
    ).toBe(false);
  });

  it('a registry that answers 404 means nothing is trusted (every envelope fails)', async () => {
    const w = await world();
    worker.use(http.get('*/api/enrollment-keys/:id', () => HttpResponse.json({ code: 'NOT_FOUND' }, { status: 404 })));
    const s = w.services();
    const good = await w.entry(0, ZERO);
    await expect(s.prepareEnvelopes?.([good])).rejects.toBeDefined();
  });

  it('the ledger link is the one the phone read from its own node, not the coordinator', async () => {
    const w = await world();
    w.handlers();
    const s = w.services({ txIndex: 77 });
    const e = await w.entry(0, ZERO);
    await s.prepareEnvelopes?.([e]);
    expect(s.ledgerIndexOf('AB'.repeat(32))).toBeUndefined(); // no tx in this record: nothing was asked
    expect(w.rpcCalls).toEqual([]);
  });
});

describe('I-31 presence goes through the contract routes', () => {
  it('reads the lawyer request and submits the signature with its nonce', async () => {
    const w = await world();
    const request = {
      method: 'zkpassport',
      lawyerNonce: 'ab'.repeat(32),
      ledgerHash: 'CD'.repeat(32),
      ledgerIndex: 1236001,
    };
    w.handlers({ 'presence.get': { status: 'open', request } });
    const s = w.services();
    expect(await s.presenceRequest()).toEqual(request);
    await s.submitPresence({ signature: 'ee'.repeat(64), ledgerIndex: 1236001 });
    const post = w.seen.find((r) => r.route === 'presence.submit');
    expect(JSON.parse(new TextDecoder().decode(post?.body))).toEqual({
      lawyerNonce: request.lawyerNonce,
      signature: 'ee'.repeat(64),
    });
    expect(post?.path).toBe(`/api/deals/${w.id}/presence/A/signature`);
  });

  it('submitting before a request was read sends nothing', async () => {
    const w = await world();
    w.handlers();
    await expect(w.services().submitPresence({ signature: 'ee'.repeat(64), ledgerIndex: 1 })).rejects.toThrow();
    expect(w.seen.filter((r) => r.route === 'presence.submit')).toHaveLength(0);
  });
});

describe('the shell key is made in the vault frame', () => {
  it('Alice gets the address of a key the page never sees; Bob has no such service', async () => {
    const w = await world();
    const alice = w.services();
    const address = await alice.createShellKey?.();
    expect(address).toMatch(/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/);
    expect(await alice.createShellKey?.()).toBe(address);
    expect(w.services({ role: 'bob' }).createShellKey).toBeUndefined();
  });
});

describe('OD-33 step 5f: the party accepts its badge with the slot account', () => {
  async function badgeWorld(over: { engine?: string; tamperSeal?: boolean } = {}) {
    const { pub, shares } = makeSlot();
    const id = dealId();
    const dbName = freshDb();
    const base = structuredClone(examplesOf('PublicDealData')[0]) as Record<string, string | number | string[]>;
    base.xPubA = bytesToHex(slotPubkey(pub)).toUpperCase();
    const publicData = base as never;
    const seal = bytesToHex(dealSeal(publicData));
    const sealed = { ...sealedDeal(pub, 'A'), walletAddress: String(base.walletAddress) };
    const prf = fakePrf();
    const vaultImpl = createVault({ role: 'alice', dbName, prf: prf.source, deals: async () => sealed });
    await vaultImpl.storeShares({
      dealId: id,
      pub,
      share1: copy(shares[0]),
      share2: { mode: 'security-key', credential: { id: 'c', transports: [] }, share: copy(shares[1]) },
    });
    const { port1, port2 } = new MessageChannel();
    serveVault(port2, vaultImpl, vaultFrameHost({ role: 'alice', dbName }));
    const vault = connectVault(port1);
    await vault.enroll(id);
    const submitted: string[] = [];
    const seen: RecordedRequest[] = [];
    worker.use(
      ...restHandlers({
        onRequest: (r) => {
          seen.push(r);
          if (r.route === 'ledger.submit') submitted.push(JSON.parse(new TextDecoder().decode(r.body)).txBlob);
        },
        responses: {
          'deals.get': {
            ...(examplesOf('route.deals.get.output')[0] as object),
            dealSeal: seal,
            walletAddress: base.walletAddress,
          },
          'deals.publicData': {
            status: 'complete',
            publicData: base,
            dealSeal: over.tamperSeal ? 'ab'.repeat(32) : seal,
            domain: `01${'ab'.repeat(64)}`,
          },
          'ledger.accountInfo': { exists: true, ledgerIndex: 900, flags: 0, sequence: 41, balanceDrops: '100000000' },
          'ledger.submit': (over.engine ?? 'tesSUCCESS').startsWith('tes')
            ? { status: 'validated', result: 'tesSUCCESS', hash: 'AB'.repeat(32), ledgerIndex: 901 }
            : { status: 'rejected', result: over.engine },
        },
      }),
    );
    const calls: string[] = [];
    const traced =
      <A extends unknown[], R>(label: string, f: (...a: A) => Promise<R>) =>
      (...a: A) => {
        calls.push(label === 'pin' ? `pin ${a[1]}` : label);
        return f(...a);
      };
    const spied = {
      ...vault,
      pinSeal: traced('pin', vault.pinSeal),
      loadDeal: traced('load', vault.loadDeal),
      signSingle: traced('sign', vault.signSingle),
    };
    const services = createPartyServices({
      dealId: id,
      role: 'alice',
      api: createApiClient({
        signRequest: (req) => vault.signApi({ dealId: id, pairId: 'p', ...req, ledgerIndex: 900 }),
      }),
      vault: spied,
      closeTime: () => 2000,
      txLedgerIndex: async () => undefined,
      validatedIndex: async () => 900,
    });
    return { services, submitted, seen, sealed, pub, calls, seal };
  }

  // OD-36 (a): the frame is given the deal only through its pinned seal, once, before the first signature.
  it('pins the recomputed seal and loads the deal in the frame once, before the first signature', async () => {
    const w = await badgeWorld();
    await w.services.acceptBadge?.();
    await w.services.acceptBadge?.();
    expect(w.calls).toEqual([`pin ${w.seal}`, 'load', 'sign', 'sign']);
  });

  it('signs nothing when the coordinator seal differs from the data (the frame is never given the deal)', async () => {
    const w = await badgeWorld({ tamperSeal: true });
    await expect(w.services.acceptBadge?.()).rejects.toThrow('SEAL_MISMATCH');
    expect(w.calls).toEqual([]);
  });

  it('builds the sealed CredentialAccept, signs it in the frame and submits the blob', async () => {
    const w = await badgeWorld();
    await w.services.acceptBadge?.();
    expect(w.submitted).toHaveLength(1);
    const { decode } = await import('xrpl');
    const tx = decode(w.submitted[0] as string) as unknown as Record<string, unknown>;
    expect(tx).toMatchObject({
      TransactionType: 'CredentialAccept',
      Issuer: w.sealed.walletAddress,
      CredentialType: bytesToHex(new TextEncoder().encode('LEGX_PARTY_A')).toUpperCase(),
      Sequence: 41,
      LastLedgerSequence: 920,
    });
    expect(tx.Account).toBe(slotAddress(w.pub));
    expect(tx.TxnSignature).toMatch(/^[0-9A-F]{128}$/);
  });

  it('a seal that does not match signs and sends nothing', async () => {
    const w = await badgeWorld({ tamperSeal: true });
    await expect(w.services.acceptBadge?.()).rejects.toThrow();
    expect(w.submitted).toEqual([]);
  });

  it('a ledger that refuses the transaction is an error, not a success', async () => {
    const w = await badgeWorld({ engine: 'tecNO_ENTRY' });
    await expect(w.services.acceptBadge?.()).rejects.toThrow(/tecNO_ENTRY/);
  });
});

describe('steps 5a to 5g: the lock sequence', () => {
  async function lockWorld(over: { noBindings?: boolean; wrongShell?: boolean; failAt?: number } = {}) {
    const { pub } = makeSlot();
    const id = dealId();
    const dbName = freshDb();
    const { port1, port2 } = new MessageChannel();
    serveVault(
      port2,
      createVault({ role: 'alice', dbName, deals: () => Promise.reject(new Error('no seal')) }),
      vaultFrameHost({ role: 'alice', dbName }),
    );
    const vault = connectVault(port1);
    await vault.enroll(id);
    const shell = await vault.shellKey(id);
    const base = structuredClone(examplesOf('PublicDealData')[0]) as Record<string, string | number | string[]>;
    base.walletAddress = over.wrongShell ? String(base.walletAddress) : shell.address;
    base.xPubA = bytesToHex(slotPubkey(pub)).toUpperCase();
    const seal = bytesToHex(dealSeal(base as never));
    const bound = (slot: string) =>
      toBase64(
        utf8ToBytes(
          JSON.stringify({
            payload: toBase64(
              utf8ToBytes(
                JSON.stringify({ predicate: { kind: 'key.bound', data: { slot, binding_sig: 'cd'.repeat(64) } } }),
              ),
            ),
          }),
        ),
      );
    const submitted: string[] = [];
    let sequence = 100;
    worker.use(
      http.get('*/api/ledger/accounts/:a', () =>
        HttpResponse.json({
          exists: true,
          ledgerIndex: 900,
          flags: 0,
          sequence: sequence++,
          balanceDrops: '100000000',
        }),
      ),
      http.post('*/api/ledger/submit', async ({ request }) => {
        submitted.push(((await request.json()) as { txBlob: string }).txBlob);
        return HttpResponse.json(
          over.failAt === submitted.length
            ? { status: 'rejected', result: 'tecNO_PERMISSION' }
            : { status: 'validated', result: 'tesSUCCESS', hash: 'AB'.repeat(32), ledgerIndex: 901 },
        );
      }),
      ...restHandlers({
        responses: {
          'deals.get': { ...(examplesOf('route.deals.get.output')[0] as object), dealSeal: seal },
          'deals.publicData': { status: 'complete', publicData: base, dealSeal: seal, domain: `01${'ab'.repeat(64)}` },
          'events.list': {
            events: over.noBindings
              ? []
              : [
                  { seq: 0, envelope: bound('A') },
                  { seq: 1, envelope: bound('B') },
                ],
          },
        },
      }),
    );
    const api = createApiClient({
      signRequest: (req) => vault.signApi({ dealId: id, pairId: 'p', ...req, ledgerIndex: 900 }),
    });
    return { id, vault, api, submitted };
  }

  it('signs the nine setup transactions in order with a rising sequence, and DisableMaster is last', async () => {
    const w = await lockWorld();
    const steps: string[] = [];
    await runLockSequence({
      api: w.api,
      vault: w.vault,
      dealId: w.id,
      validatedIndex: async () => 900,
      onStep: (s) => s.status === 'done' && steps.push(s.id),
    });
    const { decode } = await import('xrpl');
    const txs = w.submitted.map((b) => decode(b) as unknown as Record<string, unknown>);
    expect(txs.map((t) => t.TransactionType)).toEqual([
      'SignerListSet',
      'AccountSet',
      'AccountSet',
      'AccountSet',
      'AccountSet',
      'AccountSet',
      'DepositPreauth',
      'CredentialCreate',
      'CredentialCreate',
      'AccountSet',
    ]);
    expect(txs.map((t) => t.Sequence)).toEqual([100, 101, 102, 103, 104, 105, 106, 107, 108, 109]);
    expect(txs.at(-1)?.SetFlag).toBe(4);
    expect(txs.slice(2, 6).map((t) => t.SetFlag)).toEqual([12, 13, 14, 15]);
    expect(steps).toHaveLength(10);
    // the key is wiped: a further signature is refused
    await expect(
      w.vault.signShell(w.id, { TransactionType: 'AccountSet', SetFlag: 9, Account: txs[0]?.Account }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('stops at the first refused transaction and never reaches DisableMaster', async () => {
    const w = await lockWorld({ failAt: 3 });
    await expect(
      runLockSequence({ api: w.api, vault: w.vault, dealId: w.id, validatedIndex: async () => 900 }),
    ).rejects.toThrow(/tecNO_PERMISSION/);
    expect(w.submitted).toHaveLength(3);
  });

  it('refuses a sealed wallet that is not the shell this device made, and missing bindings: nothing is sent', async () => {
    const wrong = await lockWorld({ wrongShell: true });
    await expect(
      runLockSequence({ api: wrong.api, vault: wrong.vault, dealId: wrong.id, validatedIndex: async () => 900 }),
    ).rejects.toThrow('NOT_MY_SHELL');
    const none = await lockWorld({ noBindings: true });
    await expect(
      runLockSequence({ api: none.api, vault: none.vault, dealId: none.id, validatedIndex: async () => 900 }),
    ).rejects.toThrow('BINDINGS_MISSING');
    expect([...wrong.submitted, ...none.submitted]).toEqual([]);
  });
});
