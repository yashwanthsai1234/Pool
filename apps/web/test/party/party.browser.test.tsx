// The party app (P4.3-01 to 09, T-I-04) on Chromium and WebKit, in a phone-sized viewport, over MSW. The vault is the
// real vault (task 4.2) with real FROST shares; the coordinator is the only thing that lies.
import { ApiAuth } from '@legx/contracts/api';
import { presenceMsg } from '@legx/core/attest';
import { verifyClientRecords } from '@legx/core/clientRecords';
import { bytesToHex, dealSeal, hexToBytes, randomBytes } from '@legx/core/dealcore';
import { ed25519Check, leafHashOf, signEnvelope } from '@legx/core/evidence';
import { slotPubkey } from '@legx/core/frost';
import { toBase64 } from '@legx/core/pq';
import { createVault } from '@legx/vault';
import { ed25519 } from '@noble/curves/ed25519.js';
import { QueryClientProvider } from '@tanstack/react-query';
import axe from 'axe-core';
import { HttpResponse, http } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import {
  containsSecret,
  copy,
  dealId,
  exitPayment,
  fakePrf,
  freshDb,
  makeSlot,
  sealedDeal,
} from '../../../../packages/vault/test/helpers.ts';
import { createApiClient } from '../../src/lib/api.ts';
import { createQueryClient } from '../../src/lib/query.ts';
import { startMocks } from '../../src/mocks/browser.ts';
import { examplesOf } from '../../src/mocks/examples.ts';
import { type RecordedRequest, restHandlers } from '../../src/mocks/handlers.ts';
import { PartyApp } from '../../src/routes/party/-app.tsx';
import { PartyProvider, type PartyServices, type PresenceRequest } from '../../src/routes/party/-context.tsx';
import '../../src/index.css';

vi.setConfig({ testTimeout: 12_000 });
const AUTH = ApiAuth.parse(examplesOf('ApiAuth')[0]);
const EVIL = 'rHhr2iRBgp3ZzzNH4YGQ59G7VAiGPEWj7f';
const REQUIRE_DEST_TAG = 0x00020000;

let worker: Awaited<ReturnType<typeof startMocks>>;
beforeAll(async () => {
  worker = await startMocks();
});
afterEach(() => worker.resetHandlers());
afterAll(() => worker.stop());

type Overrides = {
  payoutB?: string;
  dealSeal?: (honest: string) => string;
  tamperPublicData?: (d: Record<string, unknown>) => void;
  tx?: (tx: Record<string, unknown>) => void;
  requestExtra?: Record<string, unknown>;
  accountInfo?: PartyServices['accountInfo'];
  presence?: Partial<PresenceRequest>;
  policy?: 'zk' | 'chip' | 'zk-or-chip';
  records?: unknown;
  role?: 'alice' | 'bob';
  id?: string;
  noWallet?: boolean;
};

function world(o: Overrides = {}) {
  const { pub, shares } = makeSlot();
  const id = o.id ?? dealId();
  const role = o.role ?? 'alice';
  const slot = role === 'alice' ? 'A' : 'B';
  const sealedBase = sealedDeal(pub, slot);
  const base = structuredClone(examplesOf('PublicDealData')[0]) as Record<string, string | number | string[]>;
  base.identityPolicy = o.policy ?? 'zk-or-chip';
  if (o.policy === 'chip') base.idMethodA = 'nfc-chip';
  if (o.policy === 'zk') base.idMethodB = 'zkpassport';
  base[slot === 'A' ? 'xPubA' : 'xPubB'] = bytesToHex(slotPubkey(pub)).toUpperCase();
  if (o.payoutB) base.payoutB = o.payoutB;
  const publicData = base as never;
  const seal = bytesToHex(dealSeal(publicData));
  const [bAcct, bTag] = String(base.payoutB).split(':');
  const deal = {
    ...sealedBase,
    walletAddress: String(base.walletAddress),
    payoutA: { account: String(base.payoutA) },
    payoutB: { account: bAcct as string, ...(bTag ? { tag: Number(bTag) } : {}) },
    exitAmountDrops: '250000000',
    dealSeal: hexToBytes(seal),
  };
  const prf = fakePrf();
  const vault = createVault({ role, dbName: freshDb(), prf: prf.source, deals: async () => deal as never });
  const tx: Record<string, unknown> = { ...exitPayment(deal as never), Amount: '250000000' };
  o.tx?.(tx);
  const request = {
    requestId: dealId(),
    dealId: id,
    purpose: 'pay_bob',
    unsignedTx: tx,
    lastLedger: 1236000,
    status: 'open',
    signedRoles: [],
    ...o.requestExtra,
  };
  const ready = vault.storeShares({
    dealId: id,
    pub,
    share1: copy(shares[0]),
    share2: { mode: 'security-key', credential: { id: 'cred', transports: [] }, share: copy(shares[1]) },
  });
  const seen: RecordedRequest[] = [];
  const dealView = {
    ...(examplesOf('route.deals.get.output')[0] as object),
    dealId: id,
    identityPolicy: o.policy ?? 'zk-or-chip',
    walletAddress: String(base.walletAddress),
    payoutA: String(base.payoutA),
    payoutB: String(base.payoutB),
    amountDrops: '250000000',
    dealSeal: o.dealSeal ? o.dealSeal(seal) : seal,
  };
  if (o.noWallet) delete (dealView as { walletAddress?: string }).walletAddress;
  const publicDataOut = structuredClone(base) as Record<string, unknown>;
  o.tamperPublicData?.(publicDataOut);
  const handlers = restHandlers({
    onRequest: (r) => seen.push(r),
    responses: {
      'deals.get': dealView,
      'deals.publicData': {
        status: 'complete',
        publicData: publicDataOut,
        dealSeal: seal,
        domain: `01${'ab'.repeat(64)}`,
      },
      'signatures.list': { requests: [request] },
      ...(o.records ? { 'records.list': o.records } : {}),
    },
  });
  worker.use(...handlers);
  const presence: PresenceRequest = {
    method: 'zkpassport',
    lawyerNonce: bytesToHex(randomBytes(32)),
    ledgerHash: bytesToHex(randomBytes(32)),
    ledgerIndex: 1236001,
    ...o.presence,
  };
  const sent: { signature: string; ledgerIndex: number }[] = [];
  const keySeed = randomBytes(32);
  const services: PartyServices = {
    dealId: id,
    role,
    api: createApiClient({ signRequest: async () => AUTH }),
    vault,
    accountInfo: o.accountInfo ?? (async () => ({ flags: 0 })),
    checkEnvelope: ed25519Check((k) => (k === 'key-1' ? ed25519.getPublicKey(keySeed) : undefined)),
    ledgerIndexOf: (h) => (h === HASH ? 77 : undefined),
    presenceRequest: async () => presence,
    submitPresence: async (p) => void sent.push(p),
    createShellKey: async () => String(base.walletAddress),
    acceptBadge: async () => {},
  };
  return {
    ready,
    services,
    vault,
    pub,
    shares,
    id,
    seal,
    request,
    seen,
    sent,
    presence,
    keySeed,
    tx,
    role,
    prf,
    dealView,
    publicData,
  };
}
const shows = (l: { element: () => Element }, s: string) => expect.poll(() => l.element().textContent).toContain(s);
const HASH = 'AB'.repeat(32);

async function show(w: ReturnType<typeof world>, screenLabel?: string) {
  await w.ready;
  const qc = createQueryClient();
  const screen = await render(
    <QueryClientProvider client={qc}>
      <PartyProvider value={w.services}>
        <PartyApp role={w.role} makeKey={() => {}} />
      </PartyProvider>
    </QueryClientProvider>,
  );
  await expect.element(page.getByRole('heading', { name: /your deal/ })).toBeVisible();
  if (screenLabel) await page.getByRole('button', { name: screenLabel }).click();
  return screen;
}
const approve = () => page.getByRole('button', { name: 'Approve payment' });

describe('P4.3-01 and T-I-04 the exit summary', () => {
  it('shows the decoded transaction, never the coordinator description', async () => {
    const w = world({ requestExtra: { description: `Pay 999 XRP to ${EVIL} for deal 0000` } });
    await show(w, 'Approve payment');
    await shows(page.getByTestId('destination'), 'rPPdduC9MRTrXZP1J7MQyEKKEYiFigWZ6Q (tag 12345)');
    await shows(page.getByTestId('amount'), '250 XRP');
    await shows(page.getByTestId('deal'), w.id);
    expect(document.body.textContent).not.toContain(EVIL);
  });

  it('refuses a destination that is not a sealed payout, and says why, and never asks the vault', async () => {
    const w = world({
      tx: (tx) => {
        tx.Destination = EVIL;
        delete tx.DestinationTag;
      },
      requestExtra: { description: 'Pay Bob' },
    });
    const sign = vi.spyOn(w.vault, 'signMultisig');
    await show(w, 'Approve payment');
    await shows(page.getByRole('alert'), 'not the payout address sealed in your deal');
    expect(approve().elements()).toHaveLength(0);
    expect(sign).not.toHaveBeenCalled();
  });

  it('refuses a wrong tag, a wrong amount and another wallet', async () => {
    for (const [mutate, text] of [
      [
        (tx: Record<string, unknown>) => {
          tx.DestinationTag = 1;
        },
        'not the payout address sealed',
      ],
      [
        (tx: Record<string, unknown>) => {
          tx.Amount = '999999999';
        },
        'not the amount your deal agreed',
      ],
      [
        (tx: Record<string, unknown>) => {
          tx.Account = EVIL;
        },
        'does not spend from your deal wallet',
      ],
    ] as const) {
      const w = world({ tx: mutate });
      const screen = await show(w, 'Approve payment');
      await shows(page.getByRole('alert'), text);
      await screen.unmount();
    }
  });
});

describe('P4.3-02 seal recomputed on the phone', () => {
  it('shows Seal mismatch and signs nothing when the coordinator seal differs', async () => {
    const w = world({ dealSeal: (s) => `${s.slice(0, 62)}00` });
    const sign = vi.spyOn(w.vault, 'signMultisig');
    await show(w, 'Approve payment');
    await shows(page.getByRole('alert'), 'Seal mismatch');
    expect(approve().elements()).toHaveLength(0);
    expect(sign).not.toHaveBeenCalled();
  });

  it('shows Seal mismatch when the public data was changed under the same seal', async () => {
    const w = world({
      tamperPublicData: (d) => {
        d.payoutB = `${EVIL}:1`;
      },
    });
    await show(w, 'Approve payment');
    await shows(page.getByRole('alert'), 'Seal mismatch');
  });

  it('also refuses the presence screen', async () => {
    const w = world({ dealSeal: (s) => `${s.slice(0, 62)}00` });
    await show(w, 'Passport presence');
    await shows(page.getByRole('alert'), 'Seal mismatch');
    expect(page.getByRole('button', { name: 'Confirm with your passkey' }).elements()).toHaveLength(0);
  });
});

describe('P4.3-03 destination tag warning', () => {
  it('warns before signing when the account requires a tag that the seal lacks', async () => {
    const asked: string[] = [];
    const w = world({
      payoutB: 'rPPdduC9MRTrXZP1J7MQyEKKEYiFigWZ6Q',
      tx: (tx) => {
        delete tx.DestinationTag;
      },
      accountInfo: async (a) => {
        asked.push(a);
        return { flags: REQUIRE_DEST_TAG };
      },
    });
    await show(w, 'Approve payment');
    await shows(page.getByRole('alert'), 'requires a destination tag');
    expect(asked).toEqual(['rPPdduC9MRTrXZP1J7MQyEKKEYiFigWZ6Q']);
    await expect.element(approve()).toBeDisabled();
    await page.getByRole('checkbox').click();
    await expect.element(approve()).toBeEnabled();
  });
});

describe('P4.3-04 approve a payment', () => {
  it('signs after the passkey and posts only the signer blob', async () => {
    const w = world();
    const secrets = w.shares.map((s) => copy(s).signingShare);
    await show(w, 'Approve payment');
    await approve().click();
    await vi.waitFor(() => expect(document.body.textContent).toMatch(/Signed\.|Nothing was sent/));
    await shows(page.getByRole('status'), 'Signed');
    expect(w.prf.state.calls).toBeGreaterThan(0); // the passkey was asked
    const posts = w.seen.filter((r) => r.route === 'signatures.submit');
    expect(posts).toHaveLength(1);
    const body = JSON.parse(new TextDecoder().decode(posts[0]?.body));
    expect(Object.keys(body).sort()).toEqual(['role', 'signerBlob']);
    expect(
      containsSecret(
        w.seen.map((r) => new TextDecoder().decode(r.body)),
        secrets,
      ),
    ).toBe(false);
    // the blob carries a strict signature under the slot key, over the multisign bytes of exactly this transaction
    const { decode, encodeForMultiSigning, deriveAddress } = await import('xrpl');
    const blob = decode(body.signerBlob) as {
      Signers: { Signer: { Account: string; SigningPubKey: string; TxnSignature: string } }[];
    };
    const s = blob.Signers[0]?.Signer as { Account: string; SigningPubKey: string; TxnSignature: string };
    expect(s.Account).toBe(deriveAddress(s.SigningPubKey));
    const msg = hexToBytes(encodeForMultiSigning(w.tx as never, s.Account).toLowerCase());
    expect(
      ed25519.verify(
        hexToBytes(s.TxnSignature.toLowerCase()),
        msg,
        hexToBytes(s.SigningPubKey.toLowerCase()).slice(1),
        { zip215: false },
      ),
    ).toBe(true);
  });

  it('sends nothing when the passkey is not used', async () => {
    const w = world();
    w.prf.state.fail = true;
    await show(w, 'Approve payment');
    await approve().click();
    await shows(page.getByRole('alert'), 'Nothing was sent');
    expect(w.seen.filter((r) => r.route === 'signatures.submit')).toHaveLength(0);
  });
});

describe('P4.3-05 and P4.3-09 passport presence', () => {
  it.each([
    ['zkpassport', 'Zero-knowledge passport check'],
    ['nfc-chip', 'Passport chip check'],
  ] as const)('signs presenceMsg with the slot key (%s)', async (method, label) => {
    const w = world({ presence: { method } });
    await show(w, 'Passport presence');
    await shows(page.getByTestId('method'), label);
    await expect.element(page.getByText('Your lawyer is checking your passport.')).toBeVisible();
    await page.getByRole('button', { name: 'Confirm with your passkey' }).click();
    await shows(page.getByRole('status'), `Signed at ledger ${w.presence.ledgerIndex}`);
    const msg = presenceMsg(
      hexToBytes(w.seal),
      'A',
      hexToBytes(w.presence.ledgerHash),
      hexToBytes(w.presence.lawyerNonce),
    );
    const sig = w.sent[0];
    expect(sig?.ledgerIndex).toBe(w.presence.ledgerIndex);
    expect(
      ed25519.verify(hexToBytes(sig?.signature as string), msg, slotPubkey(w.pub).slice(1), { zip215: false }),
    ).toBe(true);
  });

  it('refuses a method that the identity policy does not allow', async () => {
    const w = world({ policy: 'chip', presence: { method: 'zkpassport' } });
    await show(w, 'Passport presence');
    await shows(page.getByRole('alert'), 'does not allow this method');
    expect(w.sent).toHaveLength(0);
  });
});

describe('P4.3-06 my records', () => {
  function chain(keySeed: Uint8Array, breakAt?: number) {
    const out: { seq: number; leafHash: string; envelope: string; checks: unknown }[] = [];
    let prev = '00'.repeat(32);
    for (let seq = 0; seq < 3; seq++) {
      const predicate = {
        seq,
        prev_hash: seq === breakAt ? 'ff'.repeat(32) : prev,
        ...(seq === 1 ? { ledger: { tx_hash: HASH, ledger_index: 77 } } : {}),
        ...(seq === 2 ? { ledger: { tx_hash: HASH, ledger_index: 78 } } : {}),
      };
      const env = signEnvelope(new TextEncoder().encode(JSON.stringify({ predicate })), keySeed, 'key-1');
      const bytes = new TextEncoder().encode(JSON.stringify(env));
      const leafHash = leafHashOf(bytes);
      out.push({
        seq,
        leafHash,
        envelope: toBase64(bytes),
        checks: { signature: true, chain: true, ledger: 'linked' },
      });
      prev = leafHash;
    }
    return out;
  }

  it('shows the phone-computed signature, chain and ledger checks, matching verifyClientRecords', async () => {
    const keySeed = randomBytes(32);
    const records = chain(keySeed, 2);
    const w = world({ records: { records } });
    w.services.checkEnvelope = ed25519Check((k) => (k === 'key-1' ? ed25519.getPublicKey(keySeed) : undefined));
    await show(w, 'My records');
    const expected = verifyClientRecords(
      records.map((r) => ({
        envelopeBytes: new Uint8Array(
          atob(r.envelope)
            .split('')
            .map((c) => c.charCodeAt(0)),
        ),
        leafHash: r.leafHash,
      })),
      w.services.checkEnvelope,
      { ledgerIndexOf: w.services.ledgerIndexOf },
    );
    expect(expected.map((e) => [e.signature, e.chain, e.ledger])).toEqual([
      [true, true, 'none'],
      [true, true, 'linked'],
      [true, false, 'mismatch'],
    ]);
    for (const [i, e] of expected.entries()) {
      await expect.element(page.getByTestId(`record-${i}`)).toBeVisible();
      const row = page.getByTestId(`record-${i}`);
      const text = row.element().textContent as string;
      expect(text).toMatch(new RegExp(`Signature\\s*${e.signature ? 'PASS' : 'FAIL'}`));
      expect(text).toMatch(new RegExp(`Chain\\s*${e.chain ? 'PASS' : 'FAIL'}`));
      expect(text).toMatch(
        new RegExp(`Ledger\\s*${e.ledger === 'linked' ? 'PASS' : e.ledger === 'none' ? 'PENDING' : 'FAIL'}`),
      );
    }
    // the coordinator said all three are fine: the phone says so where it disagrees
    await shows(page.getByTestId('record-2'), "differ from the coordinator's");
    await expect
      .element(page.getByRole('link', { name: 'View on the ledger' }).first())
      .toHaveAttribute('href', `https://testnet.xrpl.org/transactions/${HASH}`);
  });
});

describe('the phone flow, with the network dropping', () => {
  it('goes home, to each screen, and back; a dropped network never looks like an empty deal and signs nothing', async () => {
    await page.viewport(390, 844);
    const w = world();
    await show(w);
    for (const l of [
      'Make my key',
      'Lock money',
      'Passport presence',
      'Accept my badge',
      'Approve payment',
      'My records',
    ])
      await expect.element(page.getByText(l).first()).toBeVisible();
    worker.use(http.get('*/api/deals/:id/signature-requests', () => HttpResponse.error()));
    await page.getByRole('button', { name: 'Approve payment' }).click();
    await shows(page.getByRole('alert'), 'Cannot reach the coordinator. Nothing was signed.');
    expect(approve().elements()).toHaveLength(0);
    worker.resetHandlers();
    worker.use(
      ...restHandlers({
        responses: {
          'deals.get': w.dealView,
          'deals.publicData': {
            status: 'complete',
            publicData: w.publicData,
            dealSeal: w.seal,
            domain: `01${'ab'.repeat(64)}`,
          },
          'signatures.list': { requests: [w.request] },
        },
      }),
    );
    await page.getByRole('button', { name: 'Try again' }).click();
    await expect.element(page.getByTestId('destination')).toBeVisible();
  });

  it('Bob has no Lock money step, and Alice can make the deal wallet', async () => {
    const bob = world({ role: 'bob' });
    const s = await show(bob);
    expect(page.getByText('Lock money').elements()).toHaveLength(0);
    await s.unmount();
    const w = world({ noWallet: true });
    await show(w, 'Lock money');
    await page.getByRole('button', { name: 'Make the deal wallet' }).click();
    await vi.waitFor(() => expect(w.seen.some((r) => r.route === 'deals.setWallet')).toBe(true));
  });

  it('with a wallet, Alice runs the setup steps and sees each one; a failure stops and says so', async () => {
    const w = world();
    w.services.runLockSetup = async (onStep) => {
      onStep({ id: '5a SignerListSet', status: 'running' });
      onStep({ id: '5a SignerListSet', status: 'done' });
      onStep({ id: '5b AccountSet', status: 'failed', detail: 'LEDGER_REFUSED tecNO_PERMISSION' });
      throw new Error('stopped');
    };
    await show(w, 'Lock money');
    await page.getByRole('button', { name: 'Set up the deal wallet' }).click();
    await expect.element(page.getByText(/5a SignerListSet/)).toBeVisible();
    await expect.element(page.getByText(/LEDGER_REFUSED tecNO_PERMISSION/)).toBeVisible();
    await expect.element(page.getByText(/nothing further was signed/)).toBeVisible();
  });
});

describe('accessibility and snapshots (P4.3-08)', () => {
  for (const [label, wait] of [
    [undefined, /your deal/],
    ['Approve payment', 'Approve payment'],
    ['Passport presence', 'Passport presence'],
    ['My records', 'My records'],
  ] as const) {
    it(`${label ?? 'home'} has no serious axe violations and matches the baseline`, async () => {
      await page.viewport(390, 844);
      const w = world({ id: '0192f0c8-3c4e-7a2b-8c3d-4e5f6a7b8c9d' });
      const screen = await show(w, label);
      await expect.element(page.getByRole('heading', { name: wait }).first()).toBeVisible();
      if (label === 'Approve payment') await expect.element(page.getByTestId('destination')).toBeVisible();
      const results = await axe.run(screen.container);
      expect(
        results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id),
      ).toEqual([]);
      await expect
        .element(page.getByRole('main'))
        .toMatchScreenshot(`party-${(label ?? 'home').toLowerCase().replace(/ /g, '-')}`);
    });
  }
});
