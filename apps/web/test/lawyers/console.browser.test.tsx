// Task 4.4 (lawyer console), controller level, in real Chromium and WebKit: P4.4-01 to 15 and the "all directions" rows.
// The deal is core's complete valid world (real FROST slots, hybrid signatures); the ports are fakes with spies.

import { GATE_CODES } from '@legx/contracts/records';
import { contractRoot } from '@legx/core/contract';
import { bytesToHex, hexToBytes, sha256, utf8ToBytes } from '@legx/core/dealcore';
import { lsf } from '@legx/core/lockcheck';
import type { ReleaseInput } from '@legx/core/releaseGate';
import { checkRelease } from '@legx/core/releaseGate';
import { buildSignedContractSeal, verifySignedContract } from '@legx/core/signedContract';
import { HttpResponse, http } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { decode } from 'xrpl';
import { ANCHOR, h32, makeWorld } from '../../../../packages/core/test/helpers/gate.ts';
import { startMocks } from '../../src/mocks/browser.ts';
import { SNAPSHOT_MAX_LAG } from '../../src/routes/lawyers/-console/gate.ts';
import { decodeSnapshot, encodeSnapshot, httpLedgerRelay } from '../../src/routes/lawyers/-console/relay.ts';
import { LAWYER_VAULT_DB } from '../../src/routes/lawyers/-console/vaults.ts';
import { LEDGER, makeConsole, mutable, NOW, OPS, slotPubOf, type World, withRoot, world } from './harness.ts';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 120_000 });
beforeAll(async () => void (await world()));

const text = (s: string) => utf8ToBytes(s);
const clauses = [text('1. Alice pays Bob 5000 XRP.'), text('2. Bob delivers the goods.')];
const salts = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
const root = contractRoot(clauses, salts);

async function contractWorld() {
  const w = await world();
  const data = withRoot(w.input.deal.data, bytesToHex(root));
  const la = await makeConsole({ role: 'LA', data, contract: { clauses, salts } });
  const lb = await makeConsole({ role: 'LB', data, contract: { clauses, salts } });
  return { data, la, lb };
}

describe('P4.4-01 sign contract', () => {
  it('shows the text, the wallet and the root it computed itself; the signatures verify in verifySignedContract', async () => {
    const { data, la, lb } = await contractWorld();
    const view = la.c.deal.contractView();
    expect(view.text).toContain('Alice pays Bob');
    expect(view.wallet).toBe(data.walletAddress);
    expect(view.rootHex).toBe(bytesToHex(root));
    const sigLA = await la.c.deal.signContract();
    const sigLB = await lb.c.deal.signContract();
    const terms = {
      contractRoot: root,
      walletAddress: data.walletAddress,
      lawyerPubA: data.lawyerPubA,
      lawyerPubB: data.lawyerPubB,
    };
    const { memoHex, uriHex } = buildSignedContractSeal(terms, { sigLA, sigLB });
    expect(verifySignedContract(terms, memoHex, uriHex)).toEqual({ ok: true });
    expect(la.spies.confirm).toHaveBeenCalledTimes(1); // the lawyer approved the decoded message first
  });

  it('refuses clauses whose root is not the sealed one, and signs nothing', async () => {
    const w = await world();
    const bad = await makeConsole({ role: 'LA', data: w.input.deal.data, contract: { clauses, salts } });
    expect(() => bad.c.deal.contractView()).toThrow('ROOT_MISMATCH');
    await expect(bad.c.deal.signContract()).rejects.toThrow('ROOT_MISMATCH');
    expect(bad.spies.slot.sign).not.toHaveBeenCalled();
  });

  it('lawyer A mints the contract NFT with the seal URI and both signatures; the transaction validates', async () => {
    const { data, la, lb } = await contractWorld();
    const sigLA = await la.c.deal.signContract();
    const sigLB = await lb.c.deal.signContract();
    const done = await la.c.deal.mintContractNft(sigLA, sigLB);
    expect(done).toMatchObject({ validated: true, result: 'tesSUCCESS' });
    const { decode } = await import('xrpl');
    const tx = decode(la.spies.submitted[0] as string) as Record<string, unknown>;
    const terms = {
      contractRoot: root,
      walletAddress: data.walletAddress,
      lawyerPubA: data.lawyerPubA,
      lawyerPubB: data.lawyerPubB,
    };
    const { uriHex } = buildSignedContractSeal(terms, { sigLA, sigLB });
    expect(tx).toMatchObject({ TransactionType: 'NFTokenMint', URI: uriHex, Account: OPS.LA.address, NFTokenTaxon: 0 });
    await expect(lb.c.deal.mintContractNft(sigLA, sigLB)).rejects.toThrow('NOT_LAWYER_A');
  });
});

describe('P4.4-11 and P4.4-12 the approval prompt', () => {
  const exitTx = (dest: string, amount: string) => ({
    TransactionType: 'Payment',
    Account: OPS.LA.address, // placeholder; the multisign encoding names the slot account
    Destination: dest,
    Amount: amount,
    DestinationTag: 7,
    Fee: '60',
    Sequence: 0,
    TicketSequence: 12,
    SigningPubKey: '',
    Flags: 0x80000000,
    LastLedgerSequence: 91_000_000,
  });

  it('the prompt shows values decoded from the bytes and their hash; the HSM request carries the approval over that hash', async () => {
    const { la } = await contractWorld();
    const sig = await la.c.deal.approveExit(exitTx(OPS.LB.address, '5000000'), {
      what: 'Payment',
      destination: OPS.LB.address,
      amount: '5000000 drops',
    });
    expect(sig).toMatch(/^[0-9A-F]{128}$/);
    const view = la.spies.confirm.mock.calls[0]?.[0];
    expect(view?.lines.join(' ')).toContain(OPS.LB.address);
    expect(view?.fields).toMatchObject({ what: 'Payment', destination: OPS.LB.address, amount: '5000000 drops' });
    const [request, approval] = la.spies.slot.sign.mock.calls[0] ?? [];
    expect(request?.kind).toBe('xrpl-multisign');
    expect(approval?.message_hash).toBe(view?.hash);
    expect(la.spies.requestApproval.mock.calls[0]?.[0]).toEqual(hexToBytes(view?.hash as string));
  });

  it('cancelling the prompt, or failing user verification, sends nothing to the HSM', async () => {
    const w = await world();
    const cancel = await makeConsole({ role: 'LA', data: w.input.deal.data, confirm: async () => false });
    await expect(cancel.c.deal.approveExit(exitTx(OPS.LB.address, '1'))).rejects.toThrow('APPROVAL_CANCELLED');
    expect(cancel.spies.slot.sign).not.toHaveBeenCalled();
    const noUv = await makeConsole({ role: 'LA', data: w.input.deal.data });
    noUv.spies.requestApproval.mockRejectedValueOnce(new Error('NotAllowedError'));
    await expect(noUv.c.deal.approveExit(exitTx(OPS.LB.address, '1'))).rejects.toThrow('APPROVAL_REFUSED');
    expect(noUv.spies.slot.sign).not.toHaveBeenCalled();
    const wrongHash = await makeConsole({ role: 'LA', data: w.input.deal.data });
    wrongHash.spies.requestApproval.mockImplementationOnce(
      async () =>
        ({
          credential_id: 'AA==',
          authenticator_data: 'AA==',
          client_data_json: 'AA==',
          signature: 'AA==',
          message_hash: '00'.repeat(32),
        }) as never,
    );
    await expect(wrongHash.c.deal.approveExit(exitTx(OPS.LB.address, '1'))).rejects.toThrow('APPROVAL_HASH_MISMATCH');
    expect(wrongHash.spies.slot.sign).not.toHaveBeenCalled();
  });

  it('P4.4-12: a description that differs from the bytes shows the mismatch and no approval is offered', async () => {
    const w = await world();
    const seen: string[][] = [];
    const c = await makeConsole({
      role: 'LA',
      data: w.input.deal.data,
      confirm: async (v) => {
        seen.push(v.mismatch);
        return false;
      },
    });
    await expect(
      c.c.deal.approveExit(exitTx(OPS.LA.address, '9000000'), {
        what: 'Payment',
        destination: OPS.LB.address,
        amount: '5000000 drops',
      }),
    ).rejects.toThrow('SUMMARY_MISMATCH');
    expect(seen[0]?.join(' ')).toContain(`the bytes pay ${OPS.LA.address}`);
    expect(seen[0]?.join(' ')).toContain('9000000 drops');
    expect(c.spies.requestApproval).not.toHaveBeenCalled();
    expect(c.spies.slot.sign).not.toHaveBeenCalled();
    await expect(c.c.deal.approveExit(exitTx(OPS.LB.address, '1'), { what: 'AccountDelete' })).rejects.toThrow(
      'SUMMARY_MISMATCH',
    );
  });

  it('a message the console cannot decode is never offered for approval', async () => {
    const w = await world();
    const c = await makeConsole({ role: 'LA', data: w.input.deal.data });
    await expect(c.c.deal.approveExit({ TransactionType: 'NotAType' })).rejects.toThrow('UNDECODABLE');
    expect(c.spies.confirm).not.toHaveBeenCalled();
  });
});

describe('P4.4-09 vault isolation', () => {
  it('each half has its own IndexedDB and role; A cannot list or sign with B shares', async () => {
    const { makeSlot, dealId, sealedDeal } = await import('../../../../packages/vault/test/helpers.ts');
    const { lawyerVault } = await import('../../src/routes/lawyers/-console/vaults.ts');
    const id = dealId();
    const { pub, shares } = makeSlot();
    const deal = sealedDeal(pub, 'LB');
    const a = lawyerVault('LA', { deals: async () => deal });
    const b = lawyerVault('LB', { deals: async () => deal });
    await b.storeShares({ dealId: id, pub, share1: shares[0], share2: { mode: 'firm-hsm' } });
    expect(await b.list()).toHaveLength(1);
    expect(await a.list()).toHaveLength(0);
    await expect(a.signFrost(id, { kind: 'tagged', tag: 'legx/contract-sign/v1', parts: [] })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    expect(LAWYER_VAULT_DB.LA).not.toBe(LAWYER_VAULT_DB.LB);
    const names = (await indexedDB.databases()).map((d) => d.name);
    expect(names).toContain(LAWYER_VAULT_DB.LB);
    void slotPubOf;
  });
});

// ---------- the release code, the gate and the release ----------

const TEST_TIMEOUT = 60_000;
const failing = (r: { findings: { ok: boolean; code: string }[] }) =>
  r.findings.filter((f) => !f.ok).map((f) => f.code);

/** Lawyer B with a release code whose condition is the escrow's, over a valid world. */
async function readyB(
  mutate?: (i: ReleaseInput, w: World) => void | Promise<void>,
  over: Partial<Parameters<typeof makeConsole>[0]> = {},
) {
  const x = await makeConsole({ role: 'LB', ...over });
  const { condition } = await x.c.deal.makeReleaseCode();
  x.input.deal.escrow.conditionHex = condition;
  for (const o of x.input.ledger.objects) if (o.LedgerEntryType === 'Escrow') o.Condition = condition;
  await mutate?.(x.input, x.w);
  return x;
}

describe('P4.4-02 the release code never leaves the browser', () => {
  it('only the condition goes out; no port call or network request carries the preimage until the EscrowFinish', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const x = await readyB();
    const preimage = x.c.deal.fulfillment().slice(8).toLowerCase();
    expect(x.spies.conditions).toHaveLength(1);
    expect(x.spies.conditions[0]).not.toContain(preimage.toUpperCase());
    const state = await x.c.gate.run();
    expect(state.canRelease).toBe(true);
    const everything = () =>
      JSON.stringify([
        x.spies.slot.sign.mock.calls,
        x.spies.requestApproval.mock.calls,
        x.spies.confirm.mock.calls,
        x.spies.evidence.fields.mock.calls,
        x.spies.evidence.attach.mock.calls,
        x.spies.publicLedger.latest.mock.calls,
        x.spies.ledger.accountSequence.mock.calls,
        x.spies.conditions,
        fetchSpy.mock.calls.map((c) => String(c[0])),
      ]).toLowerCase();
    expect(everything()).not.toContain(preimage);
    await x.c.gate.release();
    const finish = decode(x.spies.submitted[0] as string) as { Fulfillment: string };
    expect(finish.Fulfillment.toLowerCase()).toContain(preimage);
    const appendedText = x.spies.appended.map((b) => new TextDecoder().decode(b)).join('');
    expect(appendedText.toLowerCase()).not.toContain(preimage);
    fetchSpy.mockRestore();
  });

  it('only lawyer B makes a code; the code is shown only on B; the condition equals SHA-256 of it', async () => {
    const a = await makeConsole({ role: 'LA' });
    await expect(a.c.deal.makeReleaseCode()).rejects.toThrow('NOT_LAWYER_B');
    const b = await makeConsole({ role: 'LB' });
    const made = await b.c.deal.makeReleaseCode();
    expect(made.display.replaceAll(' ', '')).toBe(b.c.deal.fulfillment().slice(8));
    expect(made.condition).toBe(
      `A0258020${bytesToHex(sha256(hexToBytes(made.display.replaceAll(' ', '')))).toUpperCase()}810120`,
    );
  });

  it('OD-28: the code is handed to a new lawyer B sealed to its X-Wing key, and to nobody else', async () => {
    const { PACKAGE_SUITES, XWING_SUITE } = await import('@legx/core/pq');
    const suite = PACKAGE_SUITES[XWING_SUITE] as NonNullable<(typeof PACKAGE_SUITES)[string]>;
    const old = await readyB();
    const fresh = await makeConsole({ role: 'LB' });
    const keys = await suite.keygen();
    const eve = await suite.keygen();
    const pkg = await old.c.deal.handoverReleaseCode(keys.publicKey);
    const preimage = old.c.deal.fulfillment().slice(8).toLowerCase();
    expect(bytesToHex(pkg.ct) + bytesToHex(pkg.enc)).not.toContain(preimage);
    await expect(fresh.c.deal.receiveReleaseCode(pkg, eve.secretKey)).rejects.toThrow('OPEN_FAILED');
    expect(fresh.c.deal.hasReleaseCode()).toBe(false);
    await fresh.c.deal.receiveReleaseCode(pkg, keys.secretKey);
    expect(fresh.c.deal.condition()).toBe(old.c.deal.condition());
    const noCode = await makeConsole({ role: 'LB' });
    await expect(noCode.c.deal.handoverReleaseCode(keys.publicKey)).rejects.toThrow('NO_RELEASE_CODE');
  });
});

describe('P4.4-06 and P4.4-10 the gate list', () => {
  it('reads a snapshot through the relay (HTTP, MSW), checks the public node, and shows the 17 codes as checkRelease returns them', async () => {
    const worker = await startMocks();
    try {
      const base = await makeConsole({ role: 'LB' });
      worker.use(
        http.get(
          '*/api/deals/:id/ledger-snapshot',
          () =>
            new HttpResponse(encodeSnapshot(mutable(base.input)), { headers: { 'content-type': 'application/json' } }),
        ),
      );
      const x = await makeConsole({
        role: 'LB',
        input: base.input,
        snapshot: (id) => httpLedgerRelay((p, init) => fetch(p, init)).snapshot(id),
      });
      const state = await x.c.gate.run();
      const expected = checkRelease({ ...mutable(base.input), submitter: OPS.LB.address });
      expect(state.findings).toEqual(expected);
      expect(state.findings.map((f) => f.code)).toEqual([...GATE_CODES]);
      expect(state.findings).toHaveLength(17);
      expect(x.spies.publicLedger.hashAt).toHaveBeenCalledWith(LEDGER.index);
      expect(state.methods).toEqual({
        A: { method: 'zkpassport', label: 'Zero-knowledge' },
        B: { method: 'nfc-chip', label: 'Chip' },
      });
      const rt = decodeSnapshot(encodeSnapshot(base.input));
      expect(rt.records.passport.A).toEqual(base.input.records.passport.A);
    } finally {
      worker.stop();
    }
  });

  it('a hacked coordinator: the snapshot ledger hash differs from the public node, so the gate refuses and runs nothing', async () => {
    const x = await makeConsole({ role: 'LB', publicHash: () => 'EE'.repeat(32) });
    const state = await x.c.gate.run();
    expect(state.status).toBe('refused');
    expect(state.refusal?.code).toBe('LEDGER_MISMATCH');
    expect(state.findings).toEqual([]);
    expect(state.canRelease).toBe(false);
  });

  it('the public node cannot confirm the ledger, or the relay fails: refuses, with its reason', async () => {
    const unknown = await makeConsole({ role: 'LB', publicHash: () => undefined });
    expect((await unknown.c.gate.run()).refusal?.code).toBe('PUBLIC_LEDGER_UNAVAILABLE');
    const down = await makeConsole({
      role: 'LB',
      snapshot: async () => {
        throw new Error('502');
      },
    });
    expect((await down.c.gate.run()).refusal?.code).toBe('RELAY_FAILED');
  });

  it('the relay cannot change the deal data, the deal id or the submitter', async () => {
    const x = await makeConsole({ role: 'LB' });
    const w = await world();
    const other = await makeWorld({ sameCommitment: true });
    x.input.deal.data = other.input.deal.data; // a coordinator that swaps the sealed data
    x.input.submitter = OPS.LA.address;
    const state = await x.c.gate.run();
    expect(failing(state)).toEqual([]);
    expect(w.input.deal.data).not.toEqual(other.input.deal.data);
  });
});

type Row = [
  string,
  (i: Mut, w: World) => void | Promise<void>,
  string[],
  (() => Promise<Partial<Parameters<typeof makeConsole>[0]>>)?,
];
// biome-ignore lint/suspicious/noExplicitAny: attack rows rewrite arbitrary parts of a copied input
type Mut = any;
const ROWS: Row[] = [
  [
    'LOCK_OK',
    (i) => {
      i.ledger.account.Flags &= ~lsf.DisableMaster;
    },
    ['LOCK_OK'],
  ],
  [
    'CONTRACT_SEAL_OK',
    (i) => {
      i.ledger.mintTx.validated = false;
    },
    ['CONTRACT_SEAL_OK'],
  ],
  [
    'PASSPORT_A_OK',
    async (i, w) => {
      i.records.passport.A = await w.passport('A', { presence_sig: '11'.repeat(64) });
    },
    ['PASSPORT_A_OK'],
  ],
  [
    'PASSPORT_B_OK',
    async (i, w) => {
      i.records.passport.B = await w.passport('B', { ledger_anchor: { ...ANCHOR, ledger_index: 12345 } });
    },
    ['PASSPORT_B_OK'],
  ],
  [
    'BAR_A_OK',
    async (i, w) => {
      i.records.bar.LA = await w.bar('LA', { status: 'not_active' });
    },
    ['BAR_A_OK'],
  ],
  [
    'BAR_B_OK',
    async (i, w) => {
      i.records.bar.LB = await w.bar('LB', {}, { bar_commitment: h32(0x55) });
    },
    ['BAR_B_OK'],
  ],
  [
    'ATTORNEY_CREDENTIAL_A_OK',
    (i, w) => {
      i.ledger.credentials[0] = w.credential('LA', { CredentialType: '41' });
    },
    ['ATTORNEY_CREDENTIAL_A_OK'],
  ],
  [
    'ATTORNEY_CREDENTIAL_B_OK',
    (i, w) => {
      i.ledger.credentials[1] = w.credential('LB', { Flags: 0 });
    },
    ['ATTORNEY_CREDENTIAL_B_OK'],
  ],
  // the console submits from its own operations account, so a wrong submitter is a console holding lawyer A's account
  ['RELEASER_SEALED', () => {}, ['RELEASER_SEALED'], async () => ({ opsRole: 'LA' })],
  [
    'OPS_BINDINGS_OK',
    async (i, w) => {
      i.records.opsBound.LB = await w.event('ops.bound', { ...w.opsData('LB'), sig_ops: w.opsData('LA').sig_ops });
    },
    ['OPS_BINDINGS_OK'],
  ],
  [
    'ONBOARDING_OK',
    (i) => {
      delete i.records.onboarding.A;
    },
    ['ONBOARDING_OK'],
  ],
  [
    'IDS_DISTINCT',
    () => {},
    ['IDS_DISTINCT'],
    async () => ({ input: mutable((await makeWorld({ sameCommitment: true })).input) }),
  ],
  [
    'IDENTITY_POLICY_OK',
    async (i, w) => {
      i.records.passport.A = await w.passport('A', { method: 'nfc-chip' });
    },
    ['PASSPORT_A_OK', 'IDENTITY_POLICY_OK'],
  ],
  [
    'PQ_BINDINGS_OK',
    async (i, w) => {
      const d = w.pqData('B') as { binding: { holder_sigs: unknown[] } };
      d.binding.holder_sigs = d.binding.holder_sigs.slice(0, 1);
      i.records.pqBound.B = await w.event('pq.bound', d);
    },
    ['PQ_BINDINGS_OK'],
  ],
  [
    'SLOT_SETUP_OK',
    async (i, w) => {
      const t = w.S.LA.dkg.test_sigs as string[];
      i.records.dkgCompleted.LA = await w.event('frost.dkg.completed', {
        ...w.S.LA.dkg,
        test_sigs: [t[0], t[1], t[0]],
      });
    },
    // OD-21: lawyer A's attestation signers are checked against the slot's holder keys, which come from the same DKG
    // record, so a bad record also leaves lawyer A's onboarding and passport attestations with no signer to trust.
    ['PASSPORT_A_OK', 'ONBOARDING_OK', 'SLOT_SETUP_OK'],
  ],
];

describe('P4.4-07, 13, 15 and "all directions": each of the 15 codes failing in turn', () => {
  it('the rows cover the first 15 codes, in order; the console lists the two shipping codes too', () => {
    expect(ROWS.map((r) => r[0])).toEqual(GATE_CODES.slice(0, 15));
    expect(GATE_CODES.slice(15)).toEqual(['SHIPMENT_SIGNED_OK', 'RECEIPT_SIGNED_OK']);
  });
  it.todo(
    'DQ: rows for SHIPMENT_SIGNED_OK and RECEIPT_SIGNED_OK once the test world carries signed shipment and receipt events',
  );

  it(
    'with every input good the release button is on, and the snapshot is current',
    async () => {
      const x = await readyB();
      const s = await x.c.gate.run();
      expect(failing(s)).toEqual([]);
      expect(s.canRelease).toBe(true);
      expect(s.reason).toBeUndefined();
    },
    TEST_TIMEOUT,
  );

  it.each(ROWS)(
    '%s fails: its own FAIL line and reason, the button stays off, and release refuses',
    async (_code, change, expected, opts) => {
      const x = await readyB(
        async (i, w) => {
          await change(i, w);
        },
        (await opts?.()) ?? {},
      );
      const s = await x.c.gate.run();
      expect(failing(s).sort()).toEqual([...expected].sort());
      const line = s.findings.find((f) => f.code === expected[expected.length - 1]);
      expect(line?.ok).toBe(false);
      expect(s.canRelease).toBe(false);
      expect(s.reason).toContain(failing(s)[0] as string);
      const before = x.spies.slot.sign.mock.calls.length;
      await expect(x.c.gate.release()).rejects.toMatchObject({ code: 'RELEASE_OFF' });
      expect(x.spies.slot.sign.mock.calls.length).toBe(before);
      expect(x.spies.submitted).toEqual([]);
    },
    TEST_TIMEOUT,
  );

  it(
    'P4.4-13: identityPolicy "chip" with a zero-knowledge attestation (or a method that differs from the sealed one) shows IDENTITY_POLICY_OK FAIL',
    async () => {
      // a deal sealed for chip only: its seal cannot name zero-knowledge, so the attestation is the thing that differs
      const chipWorld = await makeWorld({ policy: 'chip', methodA: 'nfc-chip', methodB: 'nfc-chip' });
      const x = await readyB(
        async (i) => {
          i.records.passport.A = await chipWorld.passport('A', { method: 'zkpassport' });
        },
        { input: mutable(chipWorld.input) },
      );
      const s = await x.c.gate.run();
      expect(failing(s)).toEqual(['PASSPORT_A_OK', 'IDENTITY_POLICY_OK']);
      expect(s.findings.find((f) => f.code === 'IDENTITY_POLICY_OK')?.detail).toBeTruthy();
      expect(s.canRelease).toBe(false);
      expect(s.methods.A.label).toBe('Zero-knowledge');
      expect(s.methods.B.label).toBe('Chip');
    },
    TEST_TIMEOUT,
  );

  it(
    'P4.4-07: a snapshot older than the validated ledger, a missing code, and lawyer A all keep the button off, each with a reason',
    async () => {
      const stale = await readyB();
      await stale.c.gate.run();
      stale.spies.publicLedger.latest.mockResolvedValue({
        index: LEDGER.index + SNAPSHOT_MAX_LAG + 1,
        hash: 'AA'.repeat(32),
        closeTime: NOW,
      });
      const s = await stale.c.gate.refresh();
      expect(s.canRelease).toBe(false);
      expect(s.reason).toContain('older than the current validated ledger');
      await expect(stale.c.gate.release()).rejects.toMatchObject({ code: 'RELEASE_OFF' });
      stale.spies.publicLedger.latest.mockResolvedValue({
        index: LEDGER.index + SNAPSHOT_MAX_LAG,
        hash: 'AA'.repeat(32),
        closeTime: NOW,
      });
      expect((await stale.c.gate.refresh()).canRelease).toBe(true);

      const noCode = await makeConsole({ role: 'LB' });
      const n = await noCode.c.gate.run();
      expect(n.canRelease).toBe(false);
      expect(n.reason).toContain('release code');

      const a = await makeConsole({ role: 'LA' });
      const r = await a.c.gate.run();
      expect(r.canRelease).toBe(false);
      expect(r.reason).toBeTruthy(); // lawyer A's operations account is not the sealed releaser, so the gate itself says no
    },
    TEST_TIMEOUT,
  );
});

describe('P4.4-08 release', () => {
  it(
    'builds the EscrowFinish with the gate memo, signs it with the operations key, submits, and records release.performed',
    async () => {
      const x = await readyB();
      await x.c.gate.run();
      const done = await x.c.gate.release();
      expect(done).toMatchObject({ validated: true, result: 'tesSUCCESS' });
      const tx = decode(x.spies.submitted[0] as string) as Record<string, unknown> & {
        Memos: { Memo: { MemoType: string; MemoData: string } }[];
      };
      expect(tx).toMatchObject({
        TransactionType: 'EscrowFinish',
        Account: OPS.LB.address,
        Owner: x.input.deal.escrow.owner,
        OfferSequence: 7,
        Condition: x.input.deal.escrow.conditionHex,
        Fulfillment: x.c.deal.fulfillment(),
        Fee: '350',
      });
      const gateEnvelope = x.spies.appended[0] as Uint8Array;
      expect(tx.Memos[0]?.Memo).toEqual({
        MemoType: bytesToHex(utf8ToBytes('legx/release-gate/v1')).toUpperCase(),
        MemoData: bytesToHex(sha256(gateEnvelope)).toUpperCase(),
      });
      const kinds = x.spies.appended.map((b) => {
        const env = JSON.parse(new TextDecoder().decode(b)) as { payload: string };
        return (JSON.parse(atob(env.payload)) as { predicate: { kind: string } }).predicate.kind;
      });
      expect(kinds).toEqual(['release.gate.passed', 'release.performed']);
      // the gate record is signed by the slot only after the lawyer approved the decoded record
      expect(x.spies.confirm.mock.calls[0]?.[0].lines.join(' ')).toContain('release.gate.passed');
      expect(x.spies.slot.sign.mock.calls[0]?.[0].kind).toBe('gate-record');
    },
    TEST_TIMEOUT,
  );

  it(
    'a release code that does not open the escrow condition is refused before anything is signed',
    async () => {
      const x = await makeConsole({ role: 'LB' });
      await x.c.deal.makeReleaseCode();
      const s = await x.c.gate.run(); // the world escrow carries another condition
      expect(s.canRelease).toBe(true);
      await expect(x.c.gate.release()).rejects.toMatchObject({ code: 'CODE_MISMATCH' });
      expect(x.spies.slot.sign).not.toHaveBeenCalled();
      expect(x.spies.submitted).toEqual([]);
    },
    TEST_TIMEOUT,
  );

  it(
    'a finish that does not validate records no release.performed',
    async () => {
      const x = await readyB();
      x.spies.ledger.submit.mockResolvedValueOnce({
        validated: false,
        hash: '',
        ledgerIndex: 0,
        result: 'tecNO_PERMISSION',
      });
      await x.c.gate.run();
      await expect(x.c.gate.release()).rejects.toMatchObject({ code: 'FINISH_FAILED' });
      expect(x.spies.appended).toHaveLength(1);
    },
    TEST_TIMEOUT,
  );
});

void [slotPubOf, afterAll, afterEach];
