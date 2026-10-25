// The release gate rerun (DESIGN 8.8 item 10): `checkRelease` on the recorded input, covering the signed contract, the
// bindings, the bar records and the attestations. The input comes from task 1.12's own complete valid world.
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { makeWorld as makeGateWorld, mutable } from '../../../packages/core/test/helpers/gate.ts';
import { zip } from '../../../services/evidence/src/zip.ts';
import { failures, makeBundle, resign, type TestBundle, verifyLenient } from './helpers.ts';

vi.setConfig({ testTimeout: 300_000, hookTimeout: 300_000 });

/** Bytes travel as `{"$bytes": base64}` (build/ISSUES.md item 3). */
const gateJson = (input: unknown): Uint8Array =>
  new TextEncoder().encode(
    JSON.stringify(input, function (this: Record<string, unknown>, k, v) {
      const raw = this[k];
      return raw instanceof Uint8Array ? { $bytes: Buffer.from(raw).toString('base64') } : v;
    }),
  );

let b: TestBundle;
let gate: Awaited<ReturnType<typeof makeGateWorld>>;
beforeAll(async () => {
  [b, gate] = await Promise.all([makeBundle(), makeGateWorld()]);
});

describe('release gate rerun', () => {
  it('a good input passes, and each gate code is reported under its check', async () => {
    const v = await verifyLenient(zip(await resign(b, { 'release/gate-input.json': gateJson(gate.input) })), [
      '--profile',
      'production',
    ]);
    expect(failures(v)).toEqual([]);
    expect(v.code).toBe(0);
    const checks = v.report.findings.filter(
      (f) => f.file === 'release/gate-input.json' && f.status === 'pass' && f.check !== 'manifest',
    );
    expect(checks.map((f) => f.message).sort()).toHaveLength(17);
    for (const c of ['signed-contract', 'bindings', 'bar-records', 'attestations', 'delivery', 'release-gate'])
      expect(
        checks.some((f) => f.check === c),
        c,
      ).toBe(true);
  });

  it('a changed record fails, naming the file and the check', async () => {
    const bad = mutable(gate.input);
    bad.records.passport.A = bad.records.passport.B;
    const v = await verifyLenient(zip(await resign(b, { 'release/gate-input.json': gateJson(bad) })), [
      '--profile',
      'production',
    ]);
    expect(v.code).toBe(1);
    expect(failures(v).map((f) => `${f.file} ${f.check}`)).toContain('release/gate-input.json attestations');

    const noContract = mutable(gate.input);
    noContract.deal.mintTxHash = '00'.repeat(32);
    const v2 = await verifyLenient(zip(await resign(b, { 'release/gate-input.json': gateJson(noContract) })), [
      '--profile',
      'production',
    ]);
    expect(failures(v2).length).toBeGreaterThan(0);
    expect(failures(v2).every((f) => f.file === 'release/gate-input.json')).toBe(true);
  });

  it('a missing shipment, or a receipt of another shipment, fails under the delivery check (OD-37)', async () => {
    const noShip = mutable(gate.input);
    noShip.records.shipments = [];
    const swapped = mutable(gate.input);
    swapped.records.receipts = [];
    for (const [input, code] of [
      [noShip, 'SHIPMENT_SIGNED_OK'],
      [swapped, 'RECEIPT_SIGNED_OK'],
    ] as const) {
      const v = await verifyLenient(zip(await resign(b, { 'release/gate-input.json': gateJson(input) })), [
        '--profile',
        'production',
      ]);
      expect(v.code).toBe(1);
      expect(failures(v).map((f) => `${f.check} ${f.message.split(':')[0]}`)).toContain(`delivery ${code}`);
    }
  });

  it('a malformed input fails closed', async () => {
    const v = await verifyLenient(
      zip(await resign(b, { 'release/gate-input.json': new TextEncoder().encode('{"profile":1}') })),
    );
    expect(v.code).toBe(1);
    expect(failures(v).every((f) => f.file === 'release/gate-input.json')).toBe(true);
  });
});
