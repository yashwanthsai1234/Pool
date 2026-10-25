// The guided deal walkthrough of the demo profile (build/WALKTHROUGH.md): the T-I-01 role script, one step per click.
import type { Finding } from '@legx/contracts/records';

export const WALKTHROUGH_PATH = '/demo/walkthrough';
export const STEP_TOPIC = 'walkthrough.step';

export type Identity = 'zk' | 'chip';

export interface WalkthroughInput {
  readonly amountXrp: number;
  readonly identity: Identity;
}

export const STEP_IDS = [
  'enroll',
  'deal',
  'contract',
  'funding',
  'identity-keys',
  'lock',
  'shipment',
  'receipt',
  'presence',
  'gate',
  'release',
  'close',
] as const;
export type StepId = (typeof STEP_IDS)[number];

export interface StepInfo {
  readonly n: number;
  readonly id: StepId;
  readonly title: string;
  /** Who holds the keys of this step. Party and lawyer FROST shares run inside the server ("simulated phone"). */
  readonly holders: string;
  /** Set when the step is left out of this walkthrough, with the reason. `next` passes over it. */
  readonly skipped?: string;
}

export interface StepResult {
  readonly step: StepId;
  readonly n: number;
  readonly status: 'ok' | 'failed';
  readonly txHashes: readonly string[];
  /** Explorer links, one per hash, on Testnet only. */
  readonly explorer?: readonly string[];
  readonly ledgerIndex: number;
  readonly detail: string;
  readonly gate?: readonly Finding[];
  /** Bob's balance in drops around the payment (release step). */
  readonly bob?: { readonly before: string; readonly after: string };
}

export interface WalkthroughState {
  readonly id: string;
  readonly dealId: string;
  readonly ledgerDealId: string;
  /** The deal wallet (the shell account) on the ledger. */
  readonly wallet: string;
  readonly network: string;
  readonly input: WalkthroughInput;
  readonly steps: readonly StepInfo[];
  readonly results: readonly StepResult[];
  readonly status: 'ready' | 'running' | 'done' | 'failed';
}
