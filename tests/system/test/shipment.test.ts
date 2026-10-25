// SYS-SR1 to SR4 (OD-37, OD-38): ship, then receipt, then release passes; the three delivery attacks fail with the
// right code. The full deal cannot be driven through the UIs yet (see REGRESSION.md), so SR1 runs the real gate and the
// offline verifier over a complete deal world, and SR2 to SR4 run on the composed server's demo attack routes.
// Source: build/SHIP_RECEIPT.md 4 to 6
import { GATE_CODES } from '@legx/contracts/records';
import { type Event, transition } from '@legx/core/machine';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { checkRelease } from '../../../packages/core/src/releaseGate.ts';
import { makeWorld } from '../../../packages/core/test/helpers/gate.ts';
import { zip } from '../../../services/evidence/src/zip.ts';
import { failures, makeBundle, resign, verifyLenient } from '../../../tools/verifier-cli/test/helpers.ts';
import { containersUp, LEDGER_CONTAINER, PG_CONTAINER, type Stack, startStack } from '../support/stack.ts';

let stack: Stack;
beforeAll(async () => {
  if (!containersUp()) throw new Error(`start ${PG_CONTAINER} and ${LEDGER_CONTAINER} first`);
  stack = await startStack();
}, 240_000);
afterAll(async () => {
  await stack?.stop();
});

const bytesJson = (input: unknown): Uint8Array =>
  new TextEncoder().encode(
    JSON.stringify(input, function (this: Record<string, unknown>, k, v) {
      const raw = this[k];
      return raw instanceof Uint8Array ? { $bytes: Buffer.from(raw).toString('base64') } : v;
    }),
  );

describe('SYS-SR1 ship, receipt, release', () => {
  it('the states run VERIFIED, SHIPPED, RECEIVED, FUNDED, and the 17 gate codes pass, offline too', async () => {
    let d = { state: 'VERIFIED', wasLocked: true } as Parameters<typeof transition>[0];
    const steps: Event[] = [
      { t: 'SHIP_SIGNED' },
      { t: 'RECEIPT_SIGNED', condition: 'ok' },
      { t: 'RELEASE_ESCROW', gatePassed: true, submitter: 'r', releaser: 'r' },
    ];
    const seen: string[] = [];
    for (const e of steps) {
      const t = transition(d, e);
      if (!t.ok) throw new Error(t.message);
      d = t.deal;
      seen.push(d.state);
    }
    expect(seen).toEqual(['SHIPPED', 'RECEIVED', 'FUNDED']);

    const world = await makeWorld();
    const found = checkRelease(world.input);
    expect(found.map((f) => f.code)).toEqual([...GATE_CODES]);
    expect(found.every((f) => f.ok)).toBe(true);

    const b = await makeBundle();
    const v = await verifyLenient(zip(await resign(b, { 'release/gate-input.json': bytesJson(world.input) })), [
      '--profile',
      'production',
    ]);
    expect(failures(v)).toEqual([]);
    expect(v.report.findings.filter((f) => f.check === 'delivery' && f.status === 'pass')).toHaveLength(2);
  }, 300_000);
});

const attack = async (name: string) => {
  const res = await fetch(`${stack.url}/demo/attack/${name}`, { method: 'POST' });
  return { status: res.status, body: (await res.json()) as { defeated?: boolean; code?: string; detail?: string } };
};

describe('SYS-SR2 to SR4 the delivery attacks on the running server', () => {
  it.each([
    ['SYS-SR2', 'forged-receipt', 'BAD_SIGNATURE'],
    ['SYS-SR3', 'swapped-manifest', 'MANIFEST_MISMATCH'],
    ['SYS-SR4', 'release-before-receipt', 'MISSING'],
  ])(
    '%s %s is defeated with RECEIPT_SIGNED_OK (%s)',
    async (_, name, reason) => {
      const r = await attack(name);
      expect(r.status, JSON.stringify(r.body)).toBe(200);
      expect(r.body.defeated, JSON.stringify(r.body)).toBe(true);
      expect(r.body.code).toBe('RECEIPT_SIGNED_OK');
      expect(r.body.detail).toContain(reason);
    },
    180_000,
  );
});
