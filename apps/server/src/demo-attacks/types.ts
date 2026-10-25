// The attack-mode scenes of the demo profile (IMPLEMENTATION 4.5). Each scene runs real code against a fresh deal and
// reports what the system answered; `defeated` is true when the system stopped the attack as designed.
import type { Finding } from '@legx/contracts/records';

export const ATTACKS = [
  'stranger-finish',
  'master-key-on',
  'double-exit',
  'bundle-byte',
  'fake-passport',
  'stale-bar',
  'stripped-pq',
  'replayed-zk',
  'foreign-share',
  'forged-receipt',
  'swapped-manifest',
  'release-before-receipt',
] as const;
export type AttackId = (typeof ATTACKS)[number];

export interface SceneOutcome {
  readonly defeated: boolean;
  /** The ledger's engine code (`tecNO_PERMISSION`), a lock or gate code, or the library's refusal code. */
  readonly code: string;
  readonly detail: string;
  /** Lock checker or release gate findings, when the scene ends in one (the dashboard colours the item red). */
  readonly findings?: readonly Finding[];
  readonly txHash?: string;
  readonly ledgerIndex?: number;
}
export type AttackResult = SceneOutcome & { readonly attack: AttackId };
export type Scenes = Readonly<Record<AttackId, () => Promise<SceneOutcome>>>;

export const isAttack = (name: string): name is AttackId => (ATTACKS as readonly string[]).includes(name);
