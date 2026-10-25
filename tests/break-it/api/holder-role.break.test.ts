// I-S-A1: the API maps a key to a party role from its SLOT only and ignores `holder_role`. So the recovery agent's
// enrollment key of slot A authenticates as `alice`, and the firm HSM's (or partner's) key of slot LB as `lawyerB`:
// they read the client's records, open the live feed and post events in the party's name.
// Source: DESIGN 8.10 ("only the client of a side, or that client's own lawyer"); DESIGN 6.4 (the recovery agent and
// the firm HSM hold one FROST share each and act only through their own signed protocol); OD-5 (enrollment-key auth).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type Composed, compose } from '../../../apps/server/test/support/server.ts';
import { account, joinAll } from '../../../services/coordinator/test/support/lifecycle.ts';
import {
  addTx,
  append,
  call,
  holderOf,
  makeEvent,
  SHELL,
  signRequest,
} from '../../../services/coordinator/test/support/world.ts';

let c: Composed;
beforeAll(async () => {
  c = await compose();
  await joinAll(c.w, c.dealId);
}, 300_000);
afterAll(async () => c.close());

// world.ts pins holders in this order: clients [phone, passkey-same-device, recovery-agent]; lawyers [console, firm-hsm, partner].
const agentOfA = () => holderOf(c.w, 'alice', 2);
const hsmOfLB = () => holderOf(c.w, 'lawyerB', 1);

describe('I-S-A1 holder role is ignored by API authentication', () => {
  it('the recovery agent key of slot A cannot read Alice’s records', async () => {
    expect(agentOfA().holderRole).toBe('recovery-agent');
    const url = `/deals/${c.dealId}/records`;
    const res = await c.server.app.inject(signRequest(c.w, agentOfA(), 'POST', url, { dealId: c.dealId, side: 'A' }));
    expect(res.statusCode).toBe(403);
  });

  it('the firm HSM key of slot LB cannot read the deal as lawyer B', async () => {
    expect(hsmOfLB().holderRole).toBe('firm-hsm');
    const r = await call(c.w, hsmOfLB(), 'GET', `/deals/${c.dealId}`);
    expect(r.status).toBe(403);
  });

  it('the recovery agent key of slot A cannot post an event as alice', async () => {
    // shell.opened is an alice-only event (coordinator events.ts ACTORS); here the recovery agent signs and sends it.
    const data = { wallet_address: SHELL, funding_tx_hash: addTx(c.w, 'Payment', account(c.w, 'alice')) };
    const b64 = await makeEvent(c.w, c.dealId, 'alice', 'shell.opened', data, { holder: agentOfA() });
    const r = await append(c.w, c.dealId, 'alice', b64, agentOfA());
    expect(r.body).not.toMatchObject({ status: 'stored' });
    expect(r.status).toBe(403);
  });
});
