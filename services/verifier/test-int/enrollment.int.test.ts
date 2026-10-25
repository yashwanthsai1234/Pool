// DESIGN 6.3: the firm's enrollment-key list, signed and anchored by a ledger memo, served at the well-known path.
import type { AddressInfo } from 'node:net';
import { connect, fundAccount } from '@legx/xrpl';
import { ledgerPort } from '@legx/xrpl/submit';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from 'xrpl';
import { closer } from '../../../packages/xrpl/test-int/support.ts';
import {
  checkEnrollmentList,
  ENROLLMENT_LIST_PATH,
  publishEnrollmentList,
  serveEnrollmentList,
} from '../src/enrollment.ts';
import { verifierTrust } from '../src/signing.ts';
import { env, newSigner } from './support.ts';

let client: Client;
let ticker: Client;
let stop: () => Promise<void>;
beforeAll(async () => {
  client = await connect(env);
  ticker = await connect(env);
  stop = closer(ticker, 100);
});
afterAll(async () => {
  await stop();
  await ticker.disconnect();
  await client.disconnect();
});

describe('firm enrollment-key list', () => {
  it('is signed, anchored from the firm account, served, and checked by a client; tampering is caught', async () => {
    const firm = await fundAccount(env, client, 100);
    const signer = newSigner();
    const ledger = ledgerPort(client, env, { pollMs: 50, timeoutMs: 60_000 });
    const list = {
      issuer_account: firm.classicAddress,
      seq: 1,
      keys: [{ key_id: 'firm-hsm-ed-1', alg: 'ed25519' as const, public_key: 'ab'.repeat(32), valid_from: 0 }],
    };
    const published = await publishEnrollmentList({
      list,
      signer,
      ledger,
      account: { sign: async (tx) => firm.sign(tx as never).tx_blob },
    });
    const server = await serveEnrollmentList(() => published.bytes, 0);
    try {
      const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      const body = new Uint8Array(await (await fetch(url + ENROLLMENT_LIST_PATH)).arrayBuffer());
      expect((await fetch(`${url}/other`)).status).toBe(404);
      const trust = await verifierTrust(signer);
      const ok = await checkEnrollmentList({ bytes: body, trust, ledger, anchorTxHash: published.anchorTxHash });
      expect(ok).toMatchObject({ ok: true, list: { issuer_account: firm.classicAddress, seq: 1 } });

      // A list signed by someone else, the same list with one byte changed, and an anchor that is not this list's.
      const other = await checkEnrollmentList({
        bytes: body,
        trust: await verifierTrust(newSigner()),
        ledger,
        anchorTxHash: published.anchorTxHash,
      });
      expect(other).toEqual({ ok: false, code: 'BAD_SIGNATURE' });
      const tampered = Uint8Array.from(body);
      tampered[tampered.length - 5] = tampered[tampered.length - 5] === 65 ? 66 : 65;
      expect(
        (await checkEnrollmentList({ bytes: tampered, trust, ledger, anchorTxHash: published.anchorTxHash })).ok,
      ).toBe(false);
      const second = await publishEnrollmentList({
        list: { ...list, seq: 2 },
        signer,
        ledger,
        account: { sign: async (tx) => firm.sign(tx as never).tx_blob },
      });
      expect(await checkEnrollmentList({ bytes: body, trust, ledger, anchorTxHash: second.anchorTxHash })).toEqual({
        ok: false,
        code: 'ANCHOR_MISMATCH',
      });
      expect(
        await checkEnrollmentList({
          bytes: new TextEncoder().encode('garbage'),
          trust,
          ledger,
          anchorTxHash: published.anchorTxHash,
        }),
      ).toEqual({ ok: false, code: 'MALFORMED' });
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  }, 120_000);
});
