// Task 5.1 (T-F-01): the Quint model of the deal, checked from Vitest so CI covers it.
// Short checks only. The long runs (10,000 samples, Apalache, TLC) are in spec/check.sh.
// Source: https://quint.sh/docs/quint (CLI flags: typecheck, test, run, --out-itf)
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';

const ROOT = join(import.meta.dirname, '..', '..');
const SPEC = join(ROOT, 'spec', 'deal.qnt');
const CLI = join(ROOT, 'node_modules', '@informalsystems', 'quint', 'dist', 'src', 'cli.js');
const SOURCE = readFileSync(SPEC, 'utf8');

// The invariants of T-F-01a and P5.1-05, -06, -10, -11.
const INVARIANTS = [
  'invLockedBeforeFunds',
  'invFourSigs',
  'invGateBeforeFunds',
  'invOneExit',
  'invClosedFinal',
  'invTwoPassports',
  'invTwoShares',
  'invRecoveryDelay',
  'invRotateNeedsAll',
  'invOldKeyDead',
  'invUnsafeUntilRotated',
];

// Runs the Quint CLI in a fresh temporary directory, so no tool output lands in the repo.
const TMP = mkdtempSync(join(tmpdir(), 'legx-quint-'));
afterAll(() => rmSync(TMP, { recursive: true, force: true }));
const tmp = (name: string) => mkdtempSync(join(TMP, name));

function quint(args: string[]): { code: number | null; out: string } {
  const cwd = tmp('cwd-');
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}

describe('P5.1-01 and scenario tests', () => {
  it('P5.1-01: quint typecheck passes', () => {
    const r = quint(['typecheck', SPEC]);
    expect(r.out).toBe('');
    expect(r.code).toBe(0);
  });

  // P5.1-03, -04, -08, -09, -11, -13: every attacker action is disabled where it would matter,
  // and the honest paths (happy path, dispute, expiry, recovery, rotation) work.
  it('quint test: every scenario run passes', () => {
    const r = quint(['test', SPEC, '--seed', '0x5101']);
    expect(r.out).not.toMatch(/failed/);
    expect(r.out).toMatch(/34 passing/);
    expect(r.code).toBe(0);
  }, 120_000);
});

describe('T-F-01a (short): random runs keep every invariant', () => {
  it.each([
    ['init', 'stepSim'],
    ['init', 'step'],
    ['initFunded', 'step'],
  ])(
    'from %s with %s, 30 steps',
    (init, step) => {
      const r = quint([
        'run',
        SPEC,
        '--init',
        init,
        '--step',
        step,
        '--invariants',
        ...INVARIANTS,
        '--max-steps',
        '30',
        '--max-samples',
        '300',
        '--seed',
        '0x5101',
      ]);
      expect(r.out).toMatch(/No violation found/);
      expect(r.code).toBe(0);
    },
    300_000,
  );

  it('the runs reach release, award, recovery and rotation (the invariants are not vacuous)', () => {
    const r = quint([
      'run',
      SPEC,
      '--step',
      'stepSim',
      '--max-steps',
      '30',
      '--max-samples',
      '1000',
      '--seed',
      '0x5101',
      '--witnesses',
      'witReleased',
      'witAward',
      'witRecovered',
      'witChipRelease',
      'witExpiredLocked',
    ]);
    for (const w of ['witReleased', 'witAward', 'witRecovered', 'witChipRelease', 'witExpiredLocked']) {
      expect(r.out).toMatch(new RegExp(`${w} was witnessed in [1-9]\\d* trace`));
    }
  }, 300_000);
});

// P5.1-02, P5.1-07, P5.1-12 and more: remove one guard, and the matching invariant must fail with a
// printed counterexample. This proves each invariant has teeth.
interface Mutant {
  id: string;
  edits: [string, string][];
  invariant: string;
  init: 'init' | 'initFunded';
  samples: number;
}

const MUTANTS: Mutant[] = [
  {
    id: 'P5.1-02 release without the gate guard',
    edits: [
      [
        '  action release = all {\n    d.st == RECEIVED,\n    gatePasses(d.gate),\n',
        '  action release = all {\n    d.st == RECEIVED,\n',
      ],
    ],
    invariant: 'invGateBeforeFunds',
    init: 'init',
    samples: 5000,
  },
  {
    id: 'P5.1-07 slotSign with one share',
    edits: [['      valid.size() >= THRESHOLD,\n', '      valid.size() >= 1,\n']],
    invariant: 'invTwoShares',
    init: 'initFunded',
    samples: 5000,
  },
  {
    id: 'P5.1-07 release with one attestation',
    edits: [['    else if (c == "PASSPORT_B_OK") passportOk(x, "B")\n', '    else if (c == "PASSPORT_B_OK") true\n']],
    invariant: 'invTwoPassports',
    init: 'init',
    samples: 20000,
  },
  {
    id: 'P5.1-07 release accepts a method the policy forbids',
    edits: [
      ['    allowed(p, a.method),\n    a.method == onboarded,\n', ''],
      [
        '    else CLIENTS.forall(s => allowed(x.policy, x.att.get(s).method) and x.att.get(s).method == x.onboard.get(s))\n',
        '    else true\n',
      ],
    ],
    invariant: 'invTwoPassports',
    init: 'init',
    samples: 20000,
  },
  {
    id: 'P5.1-12 recoverySign at hour 0',
    edits: [['      not(viaRecovery) or sl.recHours >= DELAY,\n', '']],
    invariant: 'invRecoveryDelay',
    init: 'initFunded',
    samples: 5000,
  },
  {
    id: 'P5.1-12 recoverySign ignores recoveryCancel',
    edits: [['      not(viaRecovery) or sl.rec == RecPending,\n', '      not(viaRecovery) or sl.rec != RecNone,\n']],
    invariant: 'invRecoveryDelay',
    init: 'initFunded',
    samples: 20000,
  },
  {
    id: 'P5.1-12 rotateSlot with three slots signed',
    edits: [['    sigs.size() >= l.quorum,\n', '    sigs.size() >= l.quorum - 1,\n']],
    invariant: 'invRotateNeedsAll',
    init: 'initFunded',
    samples: 20000,
  },
  {
    id: 'P5.1-12 the old key signs after rotation',
    edits: [['    sigs.forall(x => x._2 == slots.get(x._1).epoch),\n', '']],
    invariant: 'invOldKeyDead',
    init: 'initFunded',
    samples: 50000,
  },
  {
    id: 'P5.1-11 a refresh clears unsafe',
    edits: [['{ ...sl, unsafe: sl.unsafe }', '{ ...sl, unsafe: false }']],
    invariant: 'invUnsafeUntilRotated',
    init: 'initFunded',
    samples: 5000,
  },
  {
    id: 'I3: the lock checker misses a regular key',
    edits: [
      [
        '  pure def lockCheck(l: Ledger): bool = and {\n    not(l.masterOn),\n    not(l.regularKey),\n',
        '  pure def lockCheck(l: Ledger): bool = and {\n    not(l.masterOn),\n',
      ],
    ],
    invariant: 'invLockedBeforeFunds',
    init: 'init',
    samples: 20000,
  },
  {
    id: 'I2: the ledger accepts the master key after the lock',
    edits: [['    if (byMaster) l.masterOn\n', '    if (byMaster) true\n']],
    invariant: 'invFourSigs',
    init: 'initFunded',
    samples: 5000,
  },
  {
    id: 'I1: DepositAuth does not check the sender (strangerFinish)',
    edits: [['    not(l.depositAuth) or (who == Releaser and l.preauthReleaserOnly)\n', '    true\n']],
    invariant: 'invGateBeforeFunds',
    init: 'init',
    samples: 20000,
  },
  {
    id: 'I5: a payout from a state that already paid out',
    edits: [
      [
        '          isFundedLike(d.st),\n          d.ledger.funds,\n          go({ ...n,\n            st: PAID_OUT,',
        '          go({ ...n,\n            st: PAID_OUT,',
      ],
    ],
    invariant: 'invOneExit',
    init: 'initFunded',
    samples: 5000,
  },
  {
    id: 'I6: a dispute opens on a closed deal',
    edits: [
      [
        '    d.st == FUNDED,\n    go({ ...d, st: DISPUTED',
        '    d.st.in(Set(FUNDED, CLOSED)),\n    go({ ...d, st: DISPUTED',
      ],
    ],
    invariant: 'invClosedFinal',
    init: 'initFunded',
    samples: 5000,
  },
];

function mutate(edits: [string, string][]): string {
  let text = SOURCE;
  for (const [from, to] of edits) {
    expect(text.split(from).length - 1, `the mutation target must appear once: ${from}`).toBe(1);
    text = text.replace(from, to);
  }
  return text;
}

describe('model mutations are caught', () => {
  it.each(MUTANTS.map((m) => [m.id, m] as const))(
    '%s',
    (_id, m) => {
      const dir = tmp('mutant-');
      const file = join(dir, 'deal.qnt');
      writeFileSync(file, mutate(m.edits));
      const r = quint([
        'run',
        file,
        '--init',
        m.init,
        '--step',
        'stepSim',
        '--invariants',
        m.invariant,
        '--max-steps',
        '30',
        '--max-samples',
        String(m.samples),
        '--seed',
        '0x5101',
      ]);
      expect(r.out).toMatch(/An example execution:/);
      expect(r.out).toMatch(/\[violation\]/);
      expect(r.out).toMatch(/error: Invariant violated/);
      expect(r.code).toBe(1);
    },
    600_000,
  );
});

// ITF: https://apalache-mc.org/docs/adr/015adr-trace.html
interface ItfTrace {
  vars: string[];
  states: { d: { st: { tag: string }; ev: { t: string } } }[];
}

const MACHINE_STATES = new Set([
  'DRAFT',
  'CONTRACT_SIGNED',
  'SHELL_OPEN',
  'QUARANTINED',
  'KEYS_READY',
  'WALLET_LOCKED',
  'VERIFIED',
  'SHIPPED',
  'RECEIVED',
  'FUNDED',
  'PAID_OUT',
  'REFUNDED',
  'DISPUTED',
  'EXPIRED',
  'CLOSED',
]);
const MACHINE_EVENTS = new Set([
  'SIGN_CONTRACT',
  'OPEN_SHELL',
  'FUND_QUARANTINE',
  'KEYS_MADE',
  'LOCK_WALLET',
  'VERIFY_OK',
  'SHIP_SIGNED',
  'RECEIPT_SIGNED',
  'RELEASE_ESCROW',
  'CANCEL_AFTER_PASSED',
  'PAY_BOB',
  'REFUND_ALICE',
  'OPEN_DISPUTE',
  'AWARD',
  'ABANDON',
  'CLOSE',
]);

describe('trace export for the conformance replay', () => {
  it('quint run --out-itf writes traces whose states and events use the machine.ts names', () => {
    const dir = tmp('itf-');
    const r = quint([
      'run',
      SPEC,
      '--step',
      'stepSim',
      '--max-steps',
      '30',
      '--max-samples',
      '20',
      '--n-traces',
      '20',
      '--seed',
      '0x5101',
      '--out-itf',
      join(dir, 'trace_{seq}.itf.json'),
    ]);
    expect(r.code).toBe(0);
    const files = readdirSync(dir).filter((f) => f.endsWith('.itf.json'));
    expect(files.length).toBe(20);
    for (const f of files) {
      const trace = JSON.parse(readFileSync(join(dir, f), 'utf8')) as ItfTrace;
      expect(trace.vars).toEqual(['d']);
      expect(trace.states[0]?.d.ev.t).toBe('INIT');
      for (const s of trace.states.slice(1)) {
        expect(MACHINE_STATES.has(s.d.st.tag)).toBe(true);
        expect(s.d.ev.t === 'NONE' || MACHINE_EVENTS.has(s.d.ev.t)).toBe(true);
      }
    }
  }, 300_000);

  // Think hard (IMPLEMENTATION 5.1): replay 1,000 exported traces through machine.ts and require the
  // same final state. machine.ts gains the gate guard in task 1.14.
  it.todo('after 1.14: replay 1,000 traces through packages/core/src/machine.ts');
});
