// Break-it 5.7 (confirms I-3.7-h): the composed server never integrates deal events into the transparency log, so
// checkpoints, anchors and time stamps cover no event, and a truncated or forked per-deal chain goes unseen.
// Source: DESIGN 8.2 layer 2 (every event is a leaf of the Tessera log), https://www.rfc-editor.org/rfc/rfc9162#section-2.1
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = join(import.meta.dirname, '../../..');
const sources = (dir: string): string[] =>
  readdirSync(join(root, dir), { recursive: true, encoding: 'utf8' })
    .filter((f) => f.endsWith('.ts'))
    .map((f) => readFileSync(join(root, dir, f), 'utf8'));

describe('I-3.7-h the composition integrates stored events into the log', () => {
  it('apps/server or services/coordinator calls the log service `integrate` (or wires `afterStore`)', () => {
    const code = [...sources('apps/server/src'), ...sources('services/coordinator/src')].join('\n');
    expect(/\.integrate\(|afterStore/.test(code)).toBe(true);
  });
});
