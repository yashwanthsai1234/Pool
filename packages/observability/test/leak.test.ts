// T-A-32: run a flow with a fixture passport that touches every new span and logs hostile content; then search every
// exported span and every log line for MRZ text, DG1 bytes, salts and keys.
// HONEST LIMIT: the full API flow does not exist yet (task 3.7 composes the server; E2E-P3 reruns this search over the
// real flow with `assertNoSecrets`). Here the "flow" is the nine spans plus the worst logging mistakes we can think of,
// including bypassing `withLegxSpan` and writing attributes, events and exceptions straight on the span.

import { randomBytes } from 'node:crypto';
import { Writable } from 'node:stream';
import { demoPassport } from '@legx/fixtures/demo';
import { describe, expect, it } from 'vitest';
import { createLogger } from '../src/logger.ts';
import { type LegxSpanName, SPAN_ATTRIBUTES, withLegxSpan } from '../src/spans.ts';
import { captureSpans, spanText } from './helpers/capture.ts';

const DEAL = '0192f7c2-8f3a-7c1e-9d4b-2a6e5f4c3b21';

describe('T-A-32 no passport data, salts or keys in any span or log line', () => {
  const alice = demoPassport('alice').passport;
  const [mrz1, mrz2] = [alice.mrz.slice(0, 44), alice.mrz.slice(44)];
  const dg1 = alice.dg1;
  const salt = randomBytes(32);
  const seed = randomBytes(32);
  const barSalt = randomBytes(32);

  /** Every form a leak could take: text, hex either case, base64, and long slices of each. */
  const needles = (() => {
    const forms = (b: Uint8Array) => {
      const hex = Buffer.from(b).toString('hex');
      return [hex, hex.toUpperCase(), Buffer.from(b).toString('base64'), Buffer.from(b).toString('base64url')];
    };
    const slice = (s: string) => (s.length > 40 ? [s, s.slice(0, 40), s.slice(-40)] : [s]);
    return [
      mrz1,
      mrz2,
      mrz1.slice(0, 20),
      mrz2.slice(0, 20),
      ...forms(dg1).flatMap(slice),
      ...forms(salt),
      ...forms(seed),
      ...forms(barSalt),
    ];
  })();

  const findLeaks = (text: string) => needles.filter((n) => text.includes(n));

  it('the needles are real (the fixture passport has text and bytes to look for)', () => {
    expect(mrz1).toMatch(/^P</);
    expect(dg1.length).toBeGreaterThan(80);
    expect(Buffer.from(dg1).toString('latin1')).toContain(mrz1.slice(0, 20));
  });

  it('a hostile flow leaves nothing in the exported spans or the log lines', async () => {
    const cap = captureSpans();
    const out: string[] = [];
    const log = createLogger({
      level: 'trace',
      destination: new Writable({
        write(chunk, _e, cb) {
          out.push(String(chunk));
          cb();
        },
      }),
    });

    for (const name of Object.keys(SPAN_ATTRIBUTES) as LegxSpanName[]) {
      await withLegxSpan(
        cap.tracer,
        name,
        ((SPAN_ATTRIBUTES[name] as readonly string[]).includes('deal.id') ? { 'deal.id': DEAL } : {}) as never,
        (span) => {
          // Mistakes a developer could make, in every form:
          span.setAttribute('passport.mrz', alice.mrz);
          span.setAttribute('dg1', Buffer.from(dg1).toString('hex'));
          span.setAttribute('salt', salt.toString('hex'));
          span.setAttribute('gate.finding_code', mrz2); // an allowed key carrying a bad value
          span.setAttribute('deal.state', Buffer.from(dg1).toString('base64'));
          span.addEvent('read passport', { mrz: alice.mrz, seed: seed.toString('hex') });
          span.recordException(new Error(`chip said ${mrz1} ${mrz2}`));
          log.info({ mrz: alice.mrz, dg1, dg1Hex: Buffer.from(dg1).toString('hex'), salt, seed }, `passport ${mrz1}`);
          log.warn({
            facts: { firstname: 'ALICE', birthdate: '1990-01-01' },
            barSalt: barSalt.toString('hex'),
            req: { barSalt, barNumber: 'CA-1' },
          });
          log.error(
            { err: new Error(`failed on ${mrz2}`), payload: { deep: { deeper: { dg1, secretKey: seed } } } },
            `dg1=${Buffer.from(dg1).toString('base64')}`,
          );
          throw new Error(`step failed: ${alice.mrz} ${Buffer.from(dg1).toString('hex')}`);
        },
      ).catch(() => undefined);
    }

    const spans = cap.exported();
    expect(spans).toHaveLength(Object.keys(SPAN_ATTRIBUTES).length);
    expect(out.length).toBeGreaterThan(20); // the logging really happened
    expect(findLeaks(spans.map(spanText).join('\n'))).toEqual([]);
    expect(findLeaks(out.join(''))).toEqual([]);
    // and the allow-listed, harmless things survived
    expect(spans.filter((s) => s.attributes['deal.id'] === DEAL)).toHaveLength(7);
    await cap.shutdown();
  });

  it('the search itself would find a leak (it is not vacuous)', () => {
    expect(findLeaks(`oops ${mrz1}`)).not.toEqual([]);
    expect(findLeaks(`oops ${salt.toString('hex')}`)).not.toEqual([]);
    expect(findLeaks(`oops ${Buffer.from(dg1).toString('base64')}`)).not.toEqual([]);
  });
});
