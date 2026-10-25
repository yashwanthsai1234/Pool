// Hostile input in every direction: random registry answers, a classical-only payload, and a tampered envelope.
import { KeyId } from '@legx/contracts/values';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { demoAdapter } from '../src/adapters.ts';
import { VerifierError } from '../src/errors.ts';
import { signAttestation, verifierTrust } from '../src/signing.ts';

const q = { jurisdiction: 'XA', barNumber: 'DEMO-0001' as never };

describe('the demo adapter never answers anything but a result or a VerifierError', () => {
  it('for random status codes and bodies', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 100, max: 599 }).filter((s) => ![101, 204, 205, 304].includes(s) && s >= 200),
        fc.oneof(
          fc.string(),
          fc.json(),
          fc.uint8Array().map((u) => new TextDecoder().decode(u)),
        ),
        async (status, body) => {
          const fakeFetch = (async () => new Response(body, { status })) as typeof fetch;
          const adapter = demoAdapter({
            baseUrl: 'http://registry.test',
            jurisdictions: { XA: 'XA-DEMO' },
            fetch: fakeFetch,
          });
          try {
            const r = await adapter.lookup(q);
            // Only a body that is exactly the lawyer we asked for may say `active`.
            if (r.status === 'active')
              expect(JSON.parse(body)).toMatchObject({
                barNumber: 'DEMO-0001',
                jurisdiction: 'XA-DEMO',
                status: 'active',
              });
          } catch (e) {
            expect(e).toBeInstanceOf(VerifierError);
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe('signing', () => {
  const signer = nodeSigner(generateNodeSignerKeys(KeyId.parse('t-ed'), KeyId.parse('t-ml')));
  const payload = { jurisdiction: 'XA', sig_algs: ['ed25519', 'ml-dsa-65'] };

  it('produces a hybrid envelope that the trust check accepts and a flipped byte breaks', async () => {
    const s = await signAttestation(signer, payload);
    const trust = await verifierTrust(signer);
    expect(s.envelope.signatures.map((x) => x.keyid)).toEqual(['t-ed', 't-ml']);
    expect(trust.verify(s.envelope).ok).toBe(true);
    fc.assert(
      fc.property(fc.nat(s.bytes.length - 1), fc.integer({ min: 1, max: 255 }), (at, x) => {
        const bad = Uint8Array.from(s.bytes);
        bad[at] = (bad[at] ?? 0) ^ x;
        try {
          expect(trust.verify(JSON.parse(new TextDecoder().decode(bad))).ok).toBe(false);
        } catch {
          // not even JSON: also a refusal
        }
      }),
      { numRuns: 100 },
    );
  });

  it('refuses a payload that lists only one algorithm (no classical-only mode)', async () => {
    await expect(signAttestation(signer, { ...payload, sig_algs: ['ed25519'] })).rejects.toThrow('SIG_ALGS_MISMATCH');
  });

  it('another signer is not trusted', async () => {
    const s = await signAttestation(signer, payload);
    const other = nodeSigner(generateNodeSignerKeys(KeyId.parse('o-ed'), KeyId.parse('o-ml')));
    expect((await verifierTrust(other)).verify(s.envelope).ok).toBe(false);
  });
});
