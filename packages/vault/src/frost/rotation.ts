// Rotation after "my share was stolen" (DESIGN 6.4, P4.7-20): the only real revocation. A new DKG, a 4-of-4
// `SignerListSet` signed by all four slots, a new seal, and for a lawyer slot new contract signatures and a new NFT
// (core's `rotationPlan`). Each step runs with its own check, in order, and stops at the first failure. The old slot
// key counts as retired only after the ledger validated the new signer list. The ledger work itself is tasks 2.6 and
// 2.8; the screen passes it in as step functions.
// Source: DESIGN.md 6.4 "If a share is known to be stolen"
import type { SlotName } from '@legx/core/frost';
import { type RotationStep, rotationPlan } from '@legx/core/frostRules';
import { STEP_TITLE } from './text.ts';

export type StepState = {
  step: RotationStep;
  title: string;
  status: 'waiting' | 'running' | 'done' | 'failed';
  check?: string;
};

/** One step's work; it resolves with what its check proved ("validated in ledger 123"), or throws. */
export type StepRun = () => Promise<string>;

export async function runRotation(o: {
  slot: SlotName;
  steps: Partial<Record<RotationStep, StepRun>>;
  onUpdate?: (states: StepState[], oldKeyRetired: boolean) => void;
}): Promise<{ states: StepState[]; oldKeyRetired: boolean }> {
  const states: StepState[] = rotationPlan(o.slot, 'stolen').map((step) => ({
    step,
    title: STEP_TITLE[step],
    status: 'waiting',
  }));
  let retired = false;
  const show = () =>
    o.onUpdate?.(
      states.map((s) => ({ ...s })),
      retired,
    );
  show();
  for (const s of states) {
    s.status = 'running';
    show();
    const run = o.steps[s.step];
    try {
      if (!run) throw new Error('not available');
      s.check = await run();
      s.status = 'done';
      if (s.step === 'signer-list-set-4-of-4') retired = true; // only once the ledger validated the new list
    } catch (e) {
      s.status = 'failed';
      s.check = e instanceof Error ? e.message : String(e);
      show();
      break;
    }
    show();
  }
  return { states, oldKeyRetired: retired };
}
