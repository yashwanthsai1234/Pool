// P4.5-03 (server side): every attack runs its real scene against the standalone ledger (xrpld on LEGX_45_LEDGER_WS,
// default ws://127.0.0.1:6145), is defeated with the expected code, and gives the same answer when run twice in a row
// (each run builds a fresh deal).
import { describe, expect, it } from 'vitest';
import { realScenes } from '../src/demo-attacks/scenes.ts';
import { ATTACKS, type AttackId } from '../src/demo-attacks/types.ts';

const scenes = realScenes(process.env.LEGX_45_LEDGER_WS ?? process.env.XRPLD_WS ?? 'ws://127.0.0.1:6145');
const EXPECTED: Record<AttackId, string> = {
  'stranger-finish': 'tecNO_PERMISSION',
  'master-key-on': 'MASTER_DISABLED',
  'double-exit': 'tefPAST_SEQ',
  'bundle-byte': 'FAIL:archive',
  'fake-passport': 'DS_NOT_CHAINED',
  'stale-bar': 'BAR_A_OK,BAR_B_OK',
  'stripped-pq': 'B:CROSS_SIG_MISSING',
  'replayed-zk': 'BOUND_VALUE_MISMATCH',
  'foreign-share': 'SHARE_INVALID',
};

describe('the nine scenes, run twice each', () => {
  it.each(ATTACKS)('%s is defeated both times with the same code', async (a) => {
    const first = await scenes[a]();
    const second = await scenes[a]();
    for (const r of [first, second]) {
      expect(r.defeated, `${a}: ${r.detail}`).toBe(true);
      expect(r.code).toBe(EXPECTED[a]);
    }
    if (a === 'stranger-finish' || a === 'double-exit') {
      expect(first.txHash).toMatch(/^[0-9A-F]{64}$/);
      expect(second.txHash).not.toBe(first.txHash); // a fresh deal each time, not the same transaction
    }
  });

  it('master-key-on and the two gate scenes hand findings to the dashboard', async () => {
    const lock = await scenes['master-key-on']();
    expect(lock.findings?.some((f) => f.code === 'MASTER_DISABLED' && !f.ok)).toBe(true);
    const stale = await scenes['stale-bar']();
    expect(stale.findings?.filter((f) => !f.ok).map((f) => f.code)).toEqual(['BAR_A_OK', 'BAR_B_OK']);
    expect(stale.findings).toHaveLength(15);
  });
});
