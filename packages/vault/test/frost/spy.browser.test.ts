// P4.7-09: a spy over a full DKG, signing, repair and refresh. No share or secret leaves the device in clear: the
// relay carries only HPKE-sealed round packages, commitments, transcript hashes, signature shares and statements, and no
// fetch, WebSocket, postMessage, MessagePort or console output carries a secret.
import type { KeyShare } from '@legx/core/frost';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { xwingShareCipher } from '../../src/frost/cipher.ts';
import { openerSessions } from '../../src/frost/dkg.ts';
import { FrostHolder } from '../../src/frost/holder.ts';
import { keyDirectory } from '../../src/frost/pinning.ts';
import { refreshSlot } from '../../src/frost/refresh.ts';
import { repairReceive, repairWithVault } from '../../src/frost/repair.ts';
import { decodeSigned } from '../../src/frost/wire.ts';
import { binding, containsSecret, rawRows } from '../helpers.ts';
import { clientDevices, device } from './devices.ts';

afterEach(() => vi.restoreAllMocks());

const PUBLIC_FIELDS: Record<string, string[]> = {
  'dkg.round1': ['commitment', 'proof_of_knowledge', 'kem_pub'],
  'dkg.echo': ['transcript_hash'],
  'dkg.round2': ['to', 'box'],
  'sign.begin': ['message', 'message_kind', 'commitment', 'approval', 'tagged'],
  'sign.commit': ['message_hash', 'commitment'],
  'sign.request': ['message', 'message_kind', 'commitments', 'approval'],
  'sign.share': ['message_hash', 'commitments_hash', 'share'],
  'refresh.commit': ['epoch', 'commitment', 'kem_pub'],
  'refresh.subshare': ['epoch', 'to', 'box'],
  'refresh.deleted': ['epoch', 'old_shares_hash', 'new_shares_hash'],
  'repair.hello': ['kem_pub'],
  'repair.delta': ['to', 'box', 'delta_commitments'],
  'repair.sigma': ['to', 'box'],
};
const HEADER = ['session_id', 'deal_id', 'slot', 'from', 'kind'];

function spies() {
  const out: unknown[] = [];
  const fetchSpy = vi.spyOn(globalThis, 'fetch');
  const ws = vi.spyOn(WebSocket.prototype, 'send');
  const pm = vi.spyOn(window, 'postMessage');
  const realPort = MessagePort.prototype.postMessage;
  vi.spyOn(MessagePort.prototype, 'postMessage').mockImplementation(function (
    this: MessagePort,
    m: unknown,
    o?: StructuredSerializeOptions,
  ) {
    out.push(m);
    realPort.call(this, m, o as never);
  });
  for (const k of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    const real = console[k];
    vi.spyOn(console, k).mockImplementation((...args: unknown[]) => {
      out.push(args);
      real(...args);
    });
  }
  return { out, fetchSpy, ws, pm };
}

describe('P4.7-09 spy test', () => {
  it('only public or sealed data goes out over DKG, signing, repair and refresh', { timeout: 60_000 }, async () => {
    const s = spies();
    const d = await clientDevices();
    await d.phoneVault.signFrost(d.id, binding(d.deal, 'A'));
    await Promise.all(d.finished);

    // repair the phone's share from the second device and the agent, onto a new phone
    const newPhone = await device(d.id, 1, 'phone', 'Your new phone');
    const holders = [newPhone.info, d.second.info, d.agent.info];
    d.relay.pin(newPhone.info);
    const base = {
      dealId: d.id,
      slot: 'A' as const,
      holders,
      relay: d.relay,
      pinned: keyDirectory(holders),
      pub: d.pub,
      newIndex: 1,
      helpers: [2, 3],
      timeoutMs: 8_000,
    };
    const agent = new FrostHolder({
      index: 3,
      keys: d.agent.keys,
      dealId: d.id,
      slot: 'A',
      holders,
      relay: d.relay,
      cipher: xwingShareCipher,
      pinned: keyDirectory(holders),
      timeoutMs: 8_000,
    });
    const [repaired] = await Promise.all([
      repairReceive({
        ...base,
        sessions: openerSessions(d.relay, holders),
        local: [{ index: 1, keys: newPhone.keys }],
      }),
      repairWithVault({
        ...base,
        sessions: d.relay.joiner(),
        local: [{ index: 2, keys: d.second.keys }],
        vault: d.secondVault,
      }),
      (async () =>
        agent.repairHelp(await d.relay.joiner()('repair'), {
          share: { ...d.agentShare, signingShare: d.agentShare.signingShare.slice() },
          pub: d.pub,
          helpers: [2, 3],
          newIndex: 1,
        }))(),
    ]);
    const repairedCopy = repaired.signingShare.slice();

    // refresh among the old phone, the second device and the agent
    const rBase = {
      dealId: d.id,
      slot: 'A' as const,
      holders: d.holders,
      relay: d.relay,
      pinned: keyDirectory(d.holders),
      epoch: 1,
      timeoutMs: 8_000,
    };
    const agentR = new FrostHolder({
      index: 3,
      keys: d.agent.keys,
      dealId: d.id,
      slot: 'A',
      holders: d.holders,
      relay: d.relay,
      cipher: xwingShareCipher,
      pinned: keyDirectory(d.holders),
      timeoutMs: 8_000,
    });
    const [, , agentNew] = await Promise.all([
      refreshSlot({
        ...rBase,
        sessions: openerSessions(d.relay, d.holders),
        local: [{ index: 1, keys: d.phone.keys }],
        vault: d.phoneVault,
      }),
      refreshSlot({
        ...rBase,
        sessions: d.relay.joiner(),
        local: [{ index: 2, keys: d.second.keys }],
        vault: d.secondVault,
      }),
      (async () => {
        const sid = await d.relay.joiner()('refresh');
        const o = await agentR.refresh(sid, { share: d.agentShare, pub: d.pub, participants: [1, 2, 3], epoch: 1 });
        await agentR.signDeletion(sid, o.ctx, o.pub, 1);
        return o;
      })(),
    ]);

    const secrets = [
      ...(d.clearShares as KeyShare[]).map((x) => x.signingShare),
      repairedCopy,
      agentNew.share.signingShare,
    ];
    // the relay saw only the allowed public fields, and no secret bytes anywhere
    for (const signed of d.relay.log) {
      const m = decodeSigned(signed).message as unknown as Record<string, unknown>;
      const allowed = [...HEADER, ...(PUBLIC_FIELDS[m.kind as string] ?? [])];
      expect(
        Object.keys(m).filter((k) => !allowed.includes(k)),
        String(m.kind),
      ).toEqual([]);
    }
    expect(containsSecret(d.relay.log, secrets)).toBe(false);
    expect(containsSecret(s.out, secrets)).toBe(false);
    // the test runner's own channel uses fetch and WebSocket; none of what it carried holds a secret
    expect(containsSecret([s.fetchSpy.mock.calls, s.ws.mock.calls, s.pm.mock.calls], secrets)).toBe(false);
    const rows = [
      ...(await rawRows(d.phone.dbName)),
      ...(await rawRows(d.second.dbName)),
      ...(await rawRows(newPhone.dbName)),
    ];
    expect(containsSecret(rows, secrets)).toBe(false);
  });
});
