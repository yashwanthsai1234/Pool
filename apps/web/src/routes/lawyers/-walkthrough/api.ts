// The walkthrough client. The routes exist only when the server runs the demo profile (apps/server/src/demo-walkthrough), so the
// page probes the demo attack list, exactly as the dashboard's attack panel does, and shows nothing when it is not a 200.
// Source: build/WALKTHROUGH.md "Server"
import { z } from 'zod';
import { API_BASE } from '../../../lib/paths.ts';

export interface WalkthroughForm {
  amountXrp: number;
  identity: 'zk' | 'chip';
}

const StepInfo = z.union([
  z.string().transform((title) => ({ title })),
  z.object({ title: z.string().optional(), name: z.string().optional(), id: z.string().optional() }).transform((s) => ({
    title: s.title ?? s.name ?? s.id ?? 'Step',
  })),
]);
const Created = z
  .object({ id: z.string(), dealId: z.string(), steps: z.array(StepInfo) })
  .transform((c) => ({ ...c, steps: c.steps.map((s, i) => ({ ...s, n: i + 1 })) }));
export type Created = z.infer<typeof Created>;

const Finding = z.object({ ok: z.boolean(), level: z.string(), code: z.string(), detail: z.string().optional() });
const Money = z.union([z.string(), z.number()]).transform(String);
const Step = z.object({
  status: z.string(),
  txHashes: z.array(z.string()).default([]),
  ledgerIndex: z.number().optional(),
  detail: z.string().optional(),
  gate: z.array(Finding).optional(),
  bob: z.object({ before: Money, after: Money }).optional(),
});
export type StepResult = z.infer<typeof Step>;

export interface WalkthroughClient {
  available(): Promise<boolean>;
  create(form: WalkthroughForm): Promise<Created>;
  next(id: string): Promise<StepResult>;
}

export function httpWalkthroughClient(base: string = API_BASE): WalkthroughClient {
  return {
    async available() {
      try {
        return (await fetch(`${base}/demo/attack`)).status === 200;
      } catch {
        return false;
      }
    },
    async create(form) {
      const res = await fetch(`${base}/demo/walkthrough`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return Created.parse(await res.json());
    },
    async next(id) {
      const res = await fetch(`${base}/demo/walkthrough/${encodeURIComponent(id)}/next`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return Step.parse(await res.json());
    },
  };
}
