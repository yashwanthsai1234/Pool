// The accept path must be exercised: every target has seeds, and the schema seeds are accepted by their schemas.
import { SCHEMAS } from '@legx/contracts/catalog';
import { describe, expect, it } from 'vitest';
import { targets } from '../src/index.ts';
import { checkSchemas } from '../targets/schemas.ts';

describe('seeds', () => {
  for (const t of targets) {
    it(`${t.name} has seeds`, async () => {
      expect((await t.seeds()).length).toBeGreaterThan(0);
    });
  }
  it('every contract example is accepted by some catalog schema', async () => {
    for (const t of targets.filter((x) => x.pkg === 'contracts')) {
      for (const seed of await t.seeds()) {
        expect(checkSchemas(SCHEMAS, seed), t.name).toBeGreaterThan(0);
      }
    }
  });
});
