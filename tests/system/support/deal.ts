// A deal on the running server: created by the pinned lawyer key, with one enrolled key per party pinned in.
import { ECDSA, Wallet } from 'xrpl';
import { type Holder, makeHolder, type Stack } from './stack.ts';

const addr = () => Wallet.generate(ECDSA.ed25519).classicAddress;

export interface Deal {
  dealId: string;
  alice: Holder;
  lawyerA: Holder;
}

export async function createDeal(stack: Stack): Promise<Deal> {
  const r = await stack.call(stack.lawyer, 'POST', '/deals', {
    network: 'standalone',
    identityPolicy: 'zk-or-chip',
    amountDrops: '5000000000',
    payoutA: `${addr()}:7`,
    payoutB: addr(),
    lawyerOpsA: addr(),
    lawyerOpsB: addr(),
  });
  if (r.status !== 200) throw new Error(`deals.create ${r.status}: ${JSON.stringify(r.body)}`);
  const dealId = r.body.dealId as string;
  const alice = makeHolder('alice-sys');
  const lawyerA = makeHolder('lawyerA-sys');
  await stack.pin(dealId, alice, 'A', 'phone');
  await stack.pin(dealId, lawyerA, 'LA', 'console');
  return { dealId, alice, lawyerA };
}
