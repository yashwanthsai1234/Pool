// The BarRegistryAdapter contract (IMPLEMENTATION 3.3, P3.3-01): the same suite runs against every adapter.
import type { BarLookup, BarRegistryAdapter } from '@legx/contracts/ports';
import { describe, expect, it } from 'vitest';
import { VerifierError } from '../../src/errors.ts';

export interface ContractCase {
  readonly active: BarLookup;
  readonly unknown: BarLookup;
}

export function adapterContract(name: string, make: () => Promise<{ adapter: BarRegistryAdapter } & ContractCase>) {
  describe(`BarRegistryAdapter contract: ${name}`, () => {
    it('answers an active lawyer with a well-formed source', async () => {
      const { adapter, active } = await make();
      const r = await adapter.lookup(active);
      expect(r.status).toBe('active');
      expect(r.source.evidenceSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(() => new URL(r.source.url)).not.toThrow();
    });
    it('answers an unknown bar number with not_found', async () => {
      const { adapter, unknown } = await make();
      expect((await adapter.lookup(unknown)).status).toBe('not_found');
    });
    it('never puts the bar number into the result (the source URL is signed and stored)', async () => {
      const { adapter, active } = await make();
      expect(JSON.stringify(await adapter.lookup(active))).not.toContain(active.barNumber);
    });
    it('refuses a malformed bar number with a clean error', async () => {
      const { adapter, active } = await make();
      const bad = { ...active, barNumber: '../etc/passwd' as BarLookup['barNumber'] };
      await expect(adapter.lookup(bad)).rejects.toMatchObject({ code: 'ADAPTER_BAD_REQUEST' });
      await expect(adapter.lookup(bad)).rejects.toBeInstanceOf(VerifierError);
    });
  });
}
