// The step list. The order is T-I-01's (full-flow.int.test.ts over deal.ts STAGES): the funding stage (P4) runs before
// the keys stage (P5), and deal.ts makes the identity onboarding records inside its keys stage, so WALKTHROUGH.md's
// steps 4 and 5 are one step here, after funding.
// Source: build/WALKTHROUGH.md; packages/xrpl/test-int/deal.ts (STAGES)
import type { StepId, StepInfo } from './types.ts';

const SIM = 'simulated phone: the FROST shares of Alice, Bob and both lawyers run inside the server';

const ALL: readonly Omit<StepInfo, 'n'>[] = [
  {
    id: 'enroll',
    title: 'Lawyers enroll (bar check, LEGX_ATTORNEY credentials)',
    holders: 'verifier and lawyer ops keys',
  },
  { id: 'deal', title: 'Deal created (deals.create, signed by lawyer A)', holders: 'lawyer A demo enrollment key' },
  { id: 'contract', title: 'Contract signed by both lawyers (signed-contract seal, NFT minted)', holders: SIM },
  {
    id: 'funding',
    title: "Funding: the wallet is opened and Alice's quarantine escrow",
    holders: 'Alice and the setup key',
  },
  {
    id: 'identity-keys',
    title: 'Identity onboarding, FROST DKG for all 4 slots, PQ bindings',
    holders: SIM,
  },
  {
    id: 'lock',
    title: 'Lock: SignerList 4-of-4, DepositAuth, DisableMaster; lock checker',
    holders: 'the setup key, then wiped',
  },
  { id: 'shipment', title: 'Bob signs the shipment', holders: SIM },
  { id: 'receipt', title: 'Alice signs the receipt', holders: SIM },
  { id: 'presence', title: 'Presence: the release attestations', holders: SIM },
  { id: 'gate', title: 'Release gate', holders: 'the server (core release gate)' },
  { id: 'release', title: 'Release: EscrowFinish by the sealed releaser, 4-of-4 FROST payment to Bob', holders: SIM },
  { id: 'close', title: 'Close: AccountDelete after the 256-ledger wait', holders: SIM },
];

/**
 * The steps of one walkthrough. Delivery is mandatory (OD-38): shipment and receipt always run once the shipment core is
 * ready (build/tmp/ship-core-ready at creation), and are skipped, with the reason, before that.
 */
export function plan(shipCoreReady: boolean): StepInfo[] {
  const skipped = (id: StepId) =>
    !shipCoreReady && (id === 'shipment' || id === 'receipt')
      ? { skipped: 'the shipment core is not ready (build/tmp/ship-core-ready is absent)' }
      : {};
  return ALL.map((s, i) => ({ ...s, n: i + 1, ...skipped(s.id) }));
}
