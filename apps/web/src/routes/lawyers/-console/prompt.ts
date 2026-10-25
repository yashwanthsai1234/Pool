// The approval prompt's state: `confirm` is what the console awaits, `answer` is what the dialog calls.

import { createListeners } from './listeners.ts';
import type { ApprovalView } from './ports.ts';

export interface PendingApproval {
  view: ApprovalView;
}

export function createApprovalPrompt() {
  let current: (PendingApproval & { resolve: (ok: boolean) => void }) | undefined;
  const { notify, subscribe } = createListeners();
  return {
    confirm: (view: ApprovalView) =>
      new Promise<boolean>((resolve) => {
        current?.resolve(false);
        current = { view, resolve };
        notify();
      }),
    answer(ok: boolean) {
      const c = current;
      current = undefined;
      c?.resolve(ok);
      notify();
    },
    current: (): PendingApproval | undefined => current,
    subscribe,
  };
}
export type ApprovalPrompt = ReturnType<typeof createApprovalPrompt>;
