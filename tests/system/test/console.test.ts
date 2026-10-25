// I-W-10 (R2-web): the lawyer console's requests against the real server. The console's own helper builds the operator message for
// `firm-hsm/sign` and the key signs it; the real route must accept the body (contract validation, lawyer of the slot) and
// the identity-box route must answer the lawyer of its own side. The HSM's own refusals are async and logged (tests/system sys).

import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { firmCosignRequestMessage } from '../../../apps/web/src/routes/lawyers/-console/services.ts';
import { createDeal, type Deal } from '../support/deal.ts';
import { containersUp, hex, LEDGER_CONTAINER, PG_CONTAINER, type Stack, startStack } from '../support/stack.ts';

let stack: Stack;
let deal: Deal;
beforeAll(async () => {
  if (!containersUp()) throw new Error(`start ${PG_CONTAINER} and ${LEDGER_CONTAINER} first`);
  stack = await startStack();
  deal = await createDeal(stack);
}, 240_000);
afterAll(async () => {
  await stack?.stop();
});

describe('the console against the real server', () => {
  it('firm-hsm/sign accepts the console request shape from the lawyer of the slot, and refuses another role', async () => {
    const opsSecret = new Uint8Array(randomBytes(32));
    const sessionId = hex(new Uint8Array(randomBytes(32)));
    const seal = hex(new Uint8Array(randomBytes(32)));
    const sig = ed25519.sign(
      firmCosignRequestMessage({ dealId: deal.dealId, slot: 'LA', sessionId, seal, pair: [1, 2] }),
      opsSecret,
    );
    const body = {
      slot: 'LA',
      sessionId,
      pair: [1, 2],
      seal,
      operator: { opsPub: `ED${hex(ed25519.getPublicKey(opsSecret)).toUpperCase()}`, sig: hex(sig) },
    };
    const ok = await stack.call(deal.lawyerA, 'POST', `/deals/${deal.dealId}/firm-hsm/sign`, body);
    expect(ok).toMatchObject({ status: 200, body: { status: 'started' } });
    const wrongSlot = await stack.call(deal.lawyerA, 'POST', `/deals/${deal.dealId}/firm-hsm/sign`, {
      ...body,
      slot: 'LB',
    });
    expect(wrongSlot.status).toBe(403);
    const client = await stack.call(deal.alice, 'POST', `/deals/${deal.dealId}/firm-hsm/sign`, body);
    expect(client.status).toBe(403);
  });

  it('identity-box.get answers the lawyer of side A and refuses the client and the other side', async () => {
    const mine = await stack.call(deal.lawyerA, 'GET', `/deals/${deal.dealId}/identity-box/A`);
    expect(mine).toMatchObject({ status: 200, body: { boxes: [] } });
    expect((await stack.call(deal.lawyerA, 'GET', `/deals/${deal.dealId}/identity-box/B`)).status).toBe(403);
    expect((await stack.call(deal.alice, 'GET', `/deals/${deal.dealId}/identity-box/A`)).status).toBe(403);
  });
});
