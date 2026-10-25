// The lawyer console's logic, one controller per half (lawyer A or lawyer B), each with its own vault namespace.
import { createDealActions } from './deal.ts';
import { createGate } from './gate.ts';
import { createOnboarding } from './onboarding.ts';
import { createPassportFlow } from './passport.ts';
import type { ConsoleDeps } from './ports.ts';

export function createLawyerConsole(deps: ConsoleDeps) {
  const deal = createDealActions(deps);
  return {
    role: deps.role,
    deal,
    passport: createPassportFlow(deps),
    gate: createGate(deps, deal),
    onboarding: createOnboarding(deps, deal.appendEvent),
  };
}
export type LawyerConsole = ReturnType<typeof createLawyerConsole>;
