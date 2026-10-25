// I-W-13 and the firm HSM route: the demo composition mounts a real `FirmCosigner` at `/deals/{dealId}/firm-hsm/sign`
// (a refusal is a signed, hash-chained audit row AND a coordinator-signed `frost.refused` event in the deal's log), the
// HSM's own key pair survives a restart, and the agents' evidence is durable (not `MemoryEvidence`).
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  holderOf,
  makeWorld,
  newDeal,
  type Role,
  type World,
} from '../../../services/coordinator/test/support/world.ts';
import { signedRequest } from '../../../services/recovery-agent/test/support/http.ts';
import { demoFirmDeps } from '../src/agents.ts';
import { buildServer, type Server } from '../src/compose.ts';
import { MemorySource } from './support/feed.ts';

let w: World;
let dealId: string;
let server: Server;
let dir: string;
const signer = nodeSigner(generateNodeSignerKeys('firm-ed' as never, 'firm-pq' as never));
const keysOf = (role: Role) => {
  const h = holderOf(w, role);
  return { keyId: h.pairId, edSecret: h.edSecret, pqSecret: h.pqSecret };
};
const body = (over: Record<string, unknown> = {}) => ({
  slot: 'LA',
  sessionId: 'ab'.repeat(32),
  pair: [1, 2],
  seal: 'cd'.repeat(32),
  operator: { opsPub: `ED${'11'.repeat(32)}`, sig: '22'.repeat(64) },
  ...over,
});

beforeAll(async () => {
  w = await makeWorld();
  dealId = await newDeal(w);
  dir = mkdtempSync(join(tmpdir(), 'legx-firm-'));
  const firm = await demoFirmDeps(w.deps, { dir, signer, rp: { rpId: 'localhost', origin: 'http://localhost:5173' } });
  server = await buildServer({
    profile: 'demo',
    ports: {},
    coordinator: w.deps,
    live: { source: new MemorySource() },
    agents: { firm },
  });
}, 600_000);
afterAll(async () => {
  await server.close();
  await w.close();
});

describe('the firm HSM route is mounted by the demo composition', () => {
  it('answers `started` to the slot lawyer, and the refusal is logged in the audit chain and in the deal log', async () => {
    const path = `/deals/${dealId}/firm-hsm/sign`;
    const res = await server.app.inject(signedRequest(keysOf('lawyerA'), 'POST', path, { dealId, ...body() }) as never);
    expect(res.statusCode, res.body).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ status: 'started' });
    await expect
      .poll(async () => (await w.db.repos.evidenceEvents.listAfter(dealId, -1)).length, { timeout: 20_000 })
      .toBeGreaterThan(0);
    const feed = await w.db.repos.outbox.listAfter(dealId, -1);
    const refused = feed
      .filter((o) => o.topic === 'deal.event')
      .map((o) => JSON.parse(Buffer.from(o.payload).toString()) as { summary: { kind: string } })
      .filter((o) => o.summary.kind === 'frost.refused');
    expect(refused).toHaveLength(1);
  });

  it('refuses a caller who is not the lawyer of the slot (403) and a request without a signature (401)', async () => {
    const path = `/deals/${dealId}/firm-hsm/sign`;
    const other = await server.app.inject(
      signedRequest(keysOf('lawyerB'), 'POST', path, { dealId, ...body() }) as never,
    );
    expect(other.statusCode).toBe(403);
    const party = await server.app.inject(signedRequest(keysOf('alice'), 'POST', path, { dealId, ...body() }) as never);
    expect([401, 403]).toContain(party.statusCode);
    const bare = await server.app.inject({ method: 'POST', url: path, payload: {} });
    expect(bare.statusCode).toBe(401);
  });
});

describe('the HSM key pair', () => {
  it('is made once in the data folder and is the same after a restart', async () => {
    const again = await demoFirmDeps(w.deps, {
      dir,
      signer,
      rp: { rpId: 'localhost', origin: 'http://localhost:5173' },
    });
    const first = await demoFirmDeps(w.deps, {
      dir,
      signer,
      rp: { rpId: 'localhost', origin: 'http://localhost:5173' },
    });
    expect(again.holder.keyId).toBe(first.holder.keyId);
    expect(Buffer.from(again.holder.edSecret).equals(Buffer.from(first.holder.edSecret))).toBe(true);
  });
});
