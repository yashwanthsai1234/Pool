// P3.9-01, 02, 05, 16, 17, 18: a distributed key generation through the relay with scripted participants.
import { EventPredicate } from '@legx/contracts/events';
import { verifyEd25519Strict } from '@legx/core/frost';
import { testSignMessage } from '@legx/core/frostDkg';
import { checkRelease, type ReleaseInput } from '@legx/core/releaseGate';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { slotSetup } from './support/setup.ts';
import { makeWorld, type World } from './support/world.ts';

let w: World;
beforeAll(async () => {
  w = await makeWorld();
});
afterAll(async () => {
  await w.close();
});

describe('DKG through the relay', () => {
  it('P3.9-01 three participants end with one group key, and the relay saw no share in the clear', async () => {
    const sessionId = await w.relay.openSession({
      dealId: w.dealId,
      slot: w.slot,
      purpose: 'dkg',
      participants: w.participants(),
    });
    const runs = await Promise.all([1, 2, 3].map((i) => w.holder(i).dkg(sessionId)));
    const groupKeys = runs.map((r) => r.key.public.commitments[0]);
    expect(new Set(groupKeys.map((k) => Buffer.from(k as Uint8Array).toString('hex'))).size).toBe(1);
    // the relay's stored bytes hold no signing share
    const stored = JSON.stringify(await w.relay.transcript(sessionId));
    for (const r of runs) expect(stored).not.toContain(Buffer.from(r.key.secret.signingShare).toString('hex'));
    expect(runs[0]?.round1.length).toBe(3);
  });

  it('P3.9-18 the three pairs test-sign, frost.dkg.completed holds the signatures and is a valid event', async () => {
    const w2 = await makeWorld();
    try {
      const s = await slotSetup(w2);
      expect(s.record.testSignatures).toHaveLength(3);
      for (const t of s.record.testSignatures)
        expect(verifyEd25519Strict(t.sig, testSignMessage(s.ctx, s.pub, t.pair), s.record.slotPub)).toBe(true);
      const predicate = {
        event_id: '0190a000-0000-7000-8000-000000000001',
        deal_id: w2.dealId,
        seq: 1,
        actor: { role: 'alice', key_id: 'x' },
        occurred_at: '2026-10-24T12:00:00Z',
        prev_hash: '00'.repeat(32),
        payload_commitment: '00'.repeat(32),
        sig_algs: ['ed25519', 'ml-dsa-65'],
        kind: 'frost.dkg.completed',
        data: s.data,
      };
      const parsed = EventPredicate.safeParse(predicate);
      expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
    } finally {
      await w2.close();
    }
  });

  it('P3.9-18 the release gate code SLOT_SETUP_OK passes for the slot; with a pair missing or failing it fails', async () => {
    const w2 = await makeWorld();
    try {
      const s = await slotSetup(w2);
      const dealId = w2.dealId;
      const contractRoot = '5a'.repeat(32);
      const envelope = (data: Record<string, unknown>) =>
        new TextEncoder().encode(
          JSON.stringify({
            payloadType: 'application/vnd.legx.event+json;v=1',
            payload: Buffer.from(
              JSON.stringify({
                subject: [{ name: `deal:${dealId}`, digest: { sha256: contractRoot } }],
                predicate: { deal_id: dealId, kind: 'frost.dkg.completed', data },
              }),
            ).toString('base64'),
            signatures: [],
          }),
        );
      const holders = w2.members.map((m) => ({
        ed25519: `${m.keys.keyId}#ed25519`,
        mlDsa65: `${m.keys.keyId}#ml-dsa-65`,
      }));
      const input = (data: Record<string, unknown>) =>
        ({
          deal: { id: dealId, data: { contractRoot, xPubA: s.data.group_pub, slotPolicyA: s.data.slot_policy } },
          records: {
            dkgCompleted: { A: envelope(data) },
            keys: w2.members.map((m) => ({
              keyId: `${m.keys.keyId}#ed25519`,
              alg: 'ed25519',
              publicKey: m.info.edPub.slice(1),
              validFrom: 0,
              logged: true,
            })),
            slotHolders: { A: holders, LA: holders, B: holders, LB: holders },
          },
        }) as unknown as ReleaseInput;
      const detail = (data: Record<string, unknown>) =>
        checkRelease(input(data)).find((f) => f.code === 'SLOT_SETUP_OK')?.detail;
      // slot A passes (the next slot, LA, is the first one without a record)
      expect(detail(s.data)).toBe('LA:MISSING');
      const sigs = [...(s.data.test_sigs as string[])];
      expect(detail({ ...s.data, test_sigs: [sigs[0], '00'.repeat(64), sigs[2]] })).toBe('A:TEST_SIGNATURE_INVALID');
      expect(detail({ ...s.data, test_sigs: sigs.slice(0, 2) })).toBe('A:TEST_SIGNATURE_INVALID');
    } finally {
      await w2.close();
    }
  });
});
