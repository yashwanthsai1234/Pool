// Shared by the demo scripts (task 5.6): the state file, the port table and a few probes.
// Source: IMPLEMENTATION.md sections 3 and 5.6; Node fs and crypto docs https://nodejs.org/docs/latest-v24.x/api/crypto.html
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

export const ROOT = resolve(import.meta.dirname, '..', '..');
export const STATE_FILE = resolve(ROOT, 'demo', 'state.json');

export const PORTS = {
  postgres: Number(process.env.LEGX_PG_PORT ?? 5510),
  ledger: Number(process.env.LEGX_LEDGER_PORT ?? 6113),
  registry: Number(process.env.LEGX_REGISTRY_PORT ?? 7070),
  server: Number(process.env.LEGX_PORT ?? 8710),
};
/** Container names of the dev stack; `LEGX_DEV_PREFIX` lets a second stack run beside the first (I-D-7). */
export const CONTAINERS = {
  postgres: `${process.env.LEGX_DEV_PREFIX ?? 'legx-3.7'}-pg`,
  ledger: `${process.env.LEGX_DEV_PREFIX ?? 'legx-3.7'}-xrpld`,
};
export const ROLES = ['alice', 'bob', 'lawyer-a', 'lawyer-b', 'verifier', 'arbitrator'] as const;
export const MANUAL_CHECKLIST = [
  'ZKPassport app installed on Alice phone',
  'ZKPassport app installed on Bob phone',
  'ZKPassport developer mode on, both phones',
  'ZKR mock passport loaded, both phones',
  'FIDO2 security key registered for Alice phone (or single-device confirmed)',
  'FIDO2 security key registered for Bob phone (or single-device confirmed)',
  'Tunnel up and opened from both phones on the event Wi-Fi',
  'Recovery-agent laptop up',
  'Backup video present in demo/',
] as const;

/** A demo enrollment key (see `sign.ts`). */
export interface DemoKeyState {
  keyId: string;
  ed25519Public: string;
  mlDsa65Public: string;
  ed25519Private: string;
  mlDsa65Private: string;
}

export interface DemoState {
  version: 1;
  network: 'testnet' | 'standalone';
  accounts: Record<string, { address: string; seed: string; funded: boolean }>;
  registry: { jurisdiction: string; lawyers: { role: string; barNumber: string; name: string }[] };
  passports: Record<string, { name: string; label: string; expect: string }>;
  observer: DemoKeyState;
  /** The other demo enrollment keys the server pins: `lawyer-a`, `lawyer-b` (deal creation) and `operator`. */
  keys: Record<string, DemoKeyState>;
  lawyersOnboarded: Record<string, boolean>;
  frostDkg: Record<string, boolean>;
  pqBound: boolean;
  manual: Record<string, boolean>;
  faucetCalls: number;
}

export function readState(): DemoState | undefined {
  return existsSync(STATE_FILE) ? (JSON.parse(readFileSync(STATE_FILE, 'utf8')) as DemoState) : undefined;
}

// Atomic write so a crash cannot leave half a file (every script resumes from this file).
export function writeState(s: DemoState): void {
  mkdirSync(resolve(ROOT, 'demo'), { recursive: true });
  const tmp = `${STATE_FILE}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(s, null, 2)}\n`, { mode: 0o600 });
  renameSync(tmp, STATE_FILE);
}

export function resetState(): void {
  rmSync(STATE_FILE, { force: true });
}

export const arg = (name: string): string | undefined => {
  const i = process.argv.indexOf(`--${name}`);
  return i < 0 ? undefined : (process.argv[i + 1] ?? 'true');
};

export async function probe(url: string, init?: RequestInit): Promise<{ status: number; body: string }> {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(5000) });
  return { status: res.status, body: await res.text() };
}

export const serverUrl = (): string => process.env.LEGX_SERVER_URL ?? `http://127.0.0.1:${PORTS.server}`;
export const registryUrl = (): string => process.env.LEGX_BAR_REGISTRY ?? `http://127.0.0.1:${PORTS.registry}`;
