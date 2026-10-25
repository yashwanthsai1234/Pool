// I-W-10: the real lawyer console ports, on Chromium and WebKit. A real vault frame (lawyer role, over a MessageChannel), the typed
// client over MSW, a validated snapshot from core's gate world. Nothing is injected except the network.

import { bytesToHex, dealSeal, hexToBytes } from '@legx/core/dealcore';
import { ATTEST_PAYLOAD_TYPE, PAYLOAD_TYPE, pae } from '@legx/core/evidence';
import { toBase64 } from '@legx/core/pq';
import { connectVault, createVault, enrollmentKeys, serveVault, vaultFrameHost } from '@legx/vault';
import { ed25519 } from '@noble/curves/ed25519.js';
import { HttpResponse, http } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { deriveAddress } from 'xrpl';
import { DEAL_ID, makeWorld } from '../../../../packages/core/test/helpers/gate.ts';
import { freshDb } from '../../../../packages/vault/test/helpers.ts';
import { frameApiClient } from '../../src/lib/vault-frame.tsx';
import { startMocks } from '../../src/mocks/browser.ts';
import { examplesOf } from '../../src/mocks/examples.ts';
import { type RecordedRequest, restHandlers } from '../../src/mocks/handlers.ts';
import {
  createConsoleDeps,
  firmCosignRequestMessage,
  ReleaseProofs,
} from '../../src/routes/lawyers/-console/services.ts';

let worker: Awaited<ReturnType<typeof startMocks>>;
beforeAll(async () => {
  worker = await startMocks();
});
afterEach(() => worker.resetHandlers());
afterAll(() => worker.stop());

const wire = (v: unknown) =>
  JSON.parse(JSON.stringify(v, (_k, x) => (x instanceof Uint8Array ? { $b64: toBase64(x) } : x)));

async function lawyer(role: 'LA' | 'LB' = 'LA') {
  const world = await makeWorld();
  const dbName = freshDb();
  const { port1, port2 } = new MessageChannel();
  serveVault(
    port2,
    createVault({
      role: role === 'LA' ? 'lawyerA' : 'lawyerB',
      dbName,
      deals: () => Promise.reject(new Error('no seal')),
    }),
    vaultFrameHost({ role: role === 'LA' ? 'lawyerA' : 'lawyerB', dbName }),
  );
  const vault = connectVault(port1);
  await vault.enroll(DEAL_ID, 'console-pair');
  const seen: RecordedRequest[] = [];
  const respond = (responses: Record<string, unknown> = {}) =>
    worker.use(
      ...restHandlers({
        onRequest: (r) => seen.push(r),
        responses: { 'ledger.snapshot': { releaseInput: wire(world.input) }, ...responses },
      }),
    );
  const api = frameApiClient(vault, async () => 90_000_100, DEAL_ID);
  const publicLedger = {
    latest: async () => ({ index: 90_000_100, hash: 'AA', closeTime: 800_000_000 }),
    hashAt: async () => undefined,
  };
  const make = (over: Record<string, unknown> = {}) =>
    createConsoleDeps({
      dealId: DEAL_ID,
      role,
      api,
      vault,
      opsStore: enrollmentKeys({ role: role === 'LA' ? 'lawyerA' : 'lawyerB', dbName: freshDb() }),
      publicLedger,
      confirm: async () => true,
      requestApproval: async () => {
        throw new Error('not used');
      },
      contract: { clauses: [], salts: [] },
      proofs: new ReleaseProofs(),
      ...over,
    });
  return { world, vault, seen, respond, make, api };
}

describe('I-W-10 the console is composed from the shared pieces', () => {
  it('reads the deal, the registry and the key ids of both lawyers from one validated snapshot', async () => {
    const l = await lawyer();
    l.respond();
    const deps = await l.make();
    expect(deps.deal.data).toEqual(l.world.input.deal.data);
    expect(deps.deal.profile).toBe(l.world.input.profile);
    expect(deps.registry(l.world.input.records.keys[0]?.keyId as string)?.publicKey).toEqual(
      l.world.input.records.keys[0]?.publicKey,
    );
    expect(deps.lawyerKeyIds.A).toEqual([
      l.world.input.records.slotHolders.LA[0].ed25519,
      l.world.input.records.slotHolders.LA[0].mlDsa65,
    ]);
    expect(deps.ledgerLookup(l.world.input.ledger.index)?.hash).toBe(l.world.input.ledger.hash);
    // OD-36 a: the frame holds the pinned seal and the verified data; a different seal cannot be pinned afterwards
    expect(l.seen.map((r) => r.route)).toEqual(['ledger.snapshot', 'deals.get']);
    await expect(l.vault.pinSeal(DEAL_ID, '00'.repeat(32))).rejects.toMatchObject({ code: 'INPUT_INVALID' });
  });

  it('the evidence signer is the frame: both halves, DSSE statements of this deal, nothing else', async () => {
    const l = await lawyer();
    l.respond();
    const deps = await l.make();
    const body = new TextEncoder().encode(JSON.stringify({ subject: [], predicate: { deal_id: DEAL_ID } }));
    const sig = await deps.signer.signHybrid(pae(PAYLOAD_TYPE, body), 'legx/dsse/v1');
    expect(sig.keyIds.ed25519).toBe('console-pair#ed25519');
    expect((await deps.signer.publicKeys()).keyIds).toEqual(sig.keyIds);
    await expect(deps.signer.signHybrid(pae(PAYLOAD_TYPE, body), 'legx/api-request/v1')).rejects.toMatchObject({
      code: 'CONTEXT_REFUSED',
    });
    await expect(deps.signer.signHybrid(new Uint8Array(40), 'legx/dsse/v1')).rejects.toMatchObject({
      code: 'MESSAGE_REFUSED',
    });
    const attest = new TextEncoder().encode(JSON.stringify({ deal_id: DEAL_ID }));
    await deps.signer.signHybrid(pae(ATTEST_PAYLOAD_TYPE, attest), 'legx/dsse/v1');
  });

  it('the operations key is a WebCrypto key of this origin: its address is derived from its public key', async () => {
    const l = await lawyer();
    l.respond();
    const deps = await l.make();
    expect(deps.ops.pubHex).toMatch(/^ED[0-9A-F]{64}$/);
    expect(deps.ops.address).toBe(deriveAddress(deps.ops.pubHex));
    const msg = new Uint8Array([1, 2, 3]);
    expect(ed25519.verify(await deps.ops.sign(msg), msg, hexToBytes(deps.ops.pubHex.slice(2)), { zip215: false })).toBe(
      true,
    );
  });

  it('evidence: fields come from the chain head, an event is appended as base64, a lost race is an error', async () => {
    const l = await lawyer();
    const prev = 'ab'.repeat(32);
    l.respond({
      'events.head': { nextSeq: 7, prevHash: prev },
      'events.append': { status: 'seq_taken', head: { nextSeq: 8, prevHash: prev } },
    });
    const deps = await l.make();
    const f = await deps.evidence.fields(new Uint8Array());
    expect(f).toMatchObject({ seq: 7, prev_hash: prev, payload_commitment: '00'.repeat(32) });
    expect(f.event_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    await expect(deps.evidence.append(new Uint8Array([1, 2, 3]))).rejects.toMatchObject({ code: 'SEQ_TAKEN' });
    const sent = JSON.parse(new TextDecoder().decode(l.seen.find((r) => r.route === 'events.append')?.body));
    expect(sent.envelope).toBe(toBase64(new Uint8Array([1, 2, 3])));
  });

  it("identity: the salt is opened in the frame, the public proofs go to zk.verify, the release proof is the phone's", async () => {
    const l = await lawyer();
    l.respond({ 'identityBox.get': { boxes: [] } });
    const proofs = new ReleaseProofs();
    const deps = await l.make({ proofs });
    await expect(deps.identity.salt()).rejects.toMatchObject({ code: 'NO_SALT_BOX' });
    expect(() => deps.identity.zkRequest(new Uint8Array([9]))).toThrow('NO_PROOF');
    const set = new Uint8Array([4, 5]);
    proofs.offer(new Uint8Array([9]), { stage: 'release' } as never, set);
    expect(deps.identity.zkRequest(new Uint8Array([9])).proofSet).toBe(set);
    expect(deps.identity.trustList).toEqual([]);
  });

  it("identity: with the sealed salt, zk.verify gets the opened salt and the side of this lawyer's client", async () => {
    const l = await lawyer('LA');
    const { sealSalt } = await import('@legx/core/zkIdentity');
    const salt = new Uint8Array(32).fill(0x61);
    const keys = await l.vault.enroll(DEAL_ID, 'console-pair');
    const box = await sealSalt(salt, keys.xwing, DEAL_ID, 'A');
    l.respond({
      'identityBox.get': {
        boxes: [
          {
            kind: 'zk-salt',
            box: {
              suite: box.suite,
              recipient_key_id: 'console-pair#ml-dsa-65',
              enc: toBase64(box.enc),
              ciphertext: toBase64(box.ct),
            },
          },
        ],
      },
      'zk.verify': examplesOf('route.zk.verify.output')[0],
    });
    const deps = await l.make();
    expect(await deps.identity.salt()).toEqual(salt);
    await deps.identity.zkVerify({
      stage: 'release',
      domain: 'legx.app',
      scope: 's',
      devMode: false,
      proofs: [],
      originalQuery: {},
      queryResult: {},
    } as never);
    const sent = JSON.parse(new TextDecoder().decode(l.seen.find((r) => r.route === 'zk.verify')?.body));
    expect(sent).toMatchObject({ side: 'A', zkSalt32: bytesToHex(salt) });
  });
});

describe('I-W-10 the slot: console share plus the firm HSM', () => {
  it('the operator message is the one the firm cosigner verifies', () => {
    // Vector from services/firm-cosigner `operatorRequestMessage` (node build/tmp/F4/vec.ts), kept here because that service
    // imports node:crypto and cannot load in a browser test.
    const msg = firmCosignRequestMessage({
      dealId: DEAL_ID,
      slot: 'LA',
      sessionId: 'cd'.repeat(16),
      seal: 'ab'.repeat(32),
      pair: [1, 2],
    });
    expect(bytesToHex(msg)).toBe('97ec1a464191cd07cbbb6caecd4c57aa52678df30153a5d0b62346ca8405c08e');
  });

  it('asks the HSM through firm-hsm/sign with an operator signature the HSM verifies, and hands the approval to the frame', async () => {
    const l = await lawyer();
    l.respond();
    const approval = {
      credential_id: 'AA==',
      authenticator_data: 'AA==',
      client_data_json: 'AA==',
      signature: 'AA==',
      message_hash: '11'.repeat(32),
    };
    const signSlot = vi.fn(async (_args: unknown, io: { start?: (i: unknown) => Promise<void> }) => {
      await io.start?.({ sessionId: 'cd'.repeat(16), request: { kind: 'tagged' }, approval });
      return new Uint8Array(64).fill(7);
    });
    const deps = await l.make({ vault: { ...l.vault, signSlot } });
    const request = { kind: 'tagged' as const, tag: 'legx/x', parts: [] };
    const sig = await deps.slot.sign(request, approval as never);
    expect(sig).toEqual(new Uint8Array(64).fill(7));
    const args = signSlot.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(args).toMatchObject({
      dealId: DEAL_ID,
      slot: 'LA',
      localIndex: 1,
      remote: 2,
      approval,
    });
    const roles = (args.holders as { role: string }[]).map((h) => h.role);
    expect(roles).toEqual(['console', 'firm-hsm', 'partner']);
    const sent = JSON.parse(new TextDecoder().decode(l.seen.find((r) => r.route === 'firmHsm.sign')?.body));
    const seal = bytesToHex(dealSeal(deps.deal.data));
    expect(sent).toMatchObject({ slot: 'LA', pair: [1, 2], seal, approval, operator: { opsPub: deps.ops.pubHex } });
    expect(sent.message).toBeUndefined(); // the console aggregates: the HSM gets the message in sign.begin
    const msg = firmCosignRequestMessage({
      dealId: DEAL_ID,
      slot: 'LA',
      sessionId: 'cd'.repeat(16),
      seal,
      pair: [1, 2],
    });
    expect(
      ed25519.verify(hexToBytes(sent.operator.sig), msg, hexToBytes(deps.ops.pubHex.slice(2)), { zip215: false }),
    ).toBe(true);
  });

  it('a refusal by the HSM route fails the signature', async () => {
    const l = await lawyer();
    l.respond();
    worker.use(
      http.post('*/api/deals/:id/firm-hsm/sign', () => HttpResponse.json({ code: 'FORBIDDEN' }, { status: 403 })),
    );
    const signSlot = vi.fn(async (_a: unknown, io: { start?: (i: unknown) => Promise<void> }) => {
      await io.start?.({ sessionId: 'cd'.repeat(16), request: { kind: 'tagged' } });
      return new Uint8Array(64);
    });
    const deps = await l.make({ vault: { ...l.vault, signSlot } });
    await expect(deps.slot.sign({ kind: 'tagged', tag: 't', parts: [] }, {} as never)).rejects.toBeDefined();
  });
});
