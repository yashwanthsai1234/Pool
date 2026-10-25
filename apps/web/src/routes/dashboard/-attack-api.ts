// The attack-mode client. The routes exist only when the server runs the demo profile (apps/server/src/demo-attacks):
// anything but a 200 on the list means attack mode is off and the panel is not rendered (P4.5-04).
import './-jitless.ts';
import { z } from 'zod';
import { API_BASE } from '../../lib/paths.ts';

export const ATTACKS = [
  { id: 'stranger-finish', label: 'Stranger finishes the escrow', expects: 'tecNO_PERMISSION' },
  { id: 'master-key-on', label: 'Master key left on', expects: 'lock checker turns red' },
  { id: 'double-exit', label: 'Double exit on slot S', expects: 'tefPAST_SEQ' },
  { id: 'bundle-byte', label: 'One byte of the bundle changed', expects: 'offline verifier fails' },
  { id: 'fake-passport', label: 'Fake passport (wrong CSCA)', expects: 'DS_NOT_CHAINED' },
  { id: 'stale-bar', label: 'Stale bar check', expects: 'BAR_A_OK, BAR_B_OK' },
  { id: 'stripped-pq', label: 'Post-quantum signature stripped', expects: 'PQ_BINDINGS_OK' },
  { id: 'replayed-zk', label: 'Replayed ZK release proof', expects: 'BOUND_VALUE_MISMATCH' },
  { id: 'foreign-share', label: 'FROST share from outside the slot', expects: 'SHARE_INVALID' },
  { id: 'forged-receipt', label: 'Forged receipt', expects: 'RECEIPT_SIGNED_OK' },
  { id: 'swapped-manifest', label: 'Receipt for a swapped manifest', expects: 'RECEIPT_SIGNED_OK' },
  { id: 'release-before-receipt', label: 'Release before the receipt', expects: 'refused' },
] as const;
export type AttackId = (typeof ATTACKS)[number]['id'];

const Finding = z.object({
  ok: z.boolean(),
  level: z.enum(['block', 'warn']),
  code: z.string(),
  detail: z.string().optional(),
});
export const AttackResult = z.object({
  attack: z.enum(ATTACKS.map((a) => a.id) as [AttackId, ...AttackId[]]),
  defeated: z.boolean(),
  code: z.string(),
  detail: z.string(),
  findings: z.array(Finding).optional(),
  txHash: z.string().optional(),
  ledgerIndex: z.number().optional(),
});
export type AttackResult = z.infer<typeof AttackResult>;

export interface AttackClient {
  /** True only when the server answers the attack list (the demo profile). */
  available(): Promise<boolean>;
  run(id: AttackId): Promise<AttackResult>;
}

export function httpAttackClient(base: string = API_BASE): AttackClient {
  return {
    async available() {
      try {
        const res = await fetch(`${base}/demo/attack`);
        return res.status === 200;
      } catch {
        return false;
      }
    },
    async run(id) {
      const res = await fetch(`${base}/demo/attack/${id}`, { method: 'POST' });
      if (!res.ok) throw new Error(`attack ${id} failed: HTTP ${res.status}`);
      return AttackResult.parse(await res.json());
    },
  };
}
