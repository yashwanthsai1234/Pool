// The real scenes of attack mode (IMPLEMENTATION 4.5). They reuse the attack code of the test suites (the 2.6 deal
// harness in packages/xrpl/test-int/attacks, the 1.12 gate world, the 1.17 recorded proofs, the fixture passports,
// the offline verifier) by relative import: the harness is test code and is not a package export. Every scene builds
// its own fresh deal, runs the attack, and also runs the control that proves the setup was not what stopped it.
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Finding } from '@legx/contracts/records';
import { tupleHash } from '@legx/core/dealcore';
import { SigningSession } from '@legx/core/frost';
import { passiveAuth } from '../../../../packages/core/src/passport/passiveAuth.ts';
import { checkRelease, type GateCode } from '../../../../packages/core/src/releaseGate.ts';
import { checkZkResult, releaseBoundValue, zkIdentityCommitment } from '../../../../packages/core/src/zkIdentity.ts';
import { dkgKeys } from '../../../../packages/core/test/helpers/frost.ts';
import { makeWorld, mutable, NOW } from '../../../../packages/core/test/helpers/gate.ts';
import { zkSet } from '../../../../packages/core/test/helpers/zkFixtures.ts';
import { makeBadVariants, makePassport, makeTestPki } from '../../../../packages/fixtures/src/index.ts';
import { build8 } from '../../../../packages/xrpl/src/builders/index.ts';
import { standaloneEnv } from '../../../../packages/xrpl/src/env.ts';
import { nextSlot } from '../../../../packages/xrpl/src/multisig.ts';
import { outcome, stranger } from '../../../../packages/xrpl/test-int/attacks/util.ts';
import { newDeal } from '../../../../packages/xrpl/test-int/deal.ts';
import { type Chain, openChain } from '../../../../packages/xrpl/test-int/roles.ts';
import { run as verifyBundle } from '../../../../tools/verifier-cli/src/cli.ts';
import { makeBundle } from '../../../../tools/verifier-cli/test/helpers.ts';
import type { SceneOutcome, Scenes } from './types.ts';

const hex = (s: string) => Uint8Array.from(Buffer.from(s, 'hex'));
const red = (code: GateCode, detail: string): Finding => ({ ok: false, level: 'block', code, detail });
const txOf = (r: { status: string; hash?: string; ledgerIndex?: number }) =>
  r.status === 'validated' ? { txHash: r.hash, ledgerIndex: r.ledgerIndex } : {};

/** One fresh controlled chain per scene run; the standalone ledger is `ledgerWs`. */
async function onLedger<T>(ledgerWs: string, fn: (c: Chain) => Promise<T>): Promise<T> {
  const c = await openChain(standaloneEnv(ledgerWs));
  try {
    return await fn(c);
  } finally {
    await c.close();
  }
}

// ---------- on the ledger ----------

// Source: https://xrpl.org/docs/references/protocol/transactions/types/escrowfinish ; DESIGN D4, T-A-07
const strangerFinish = (ws: string) => () =>
  onLedger(ws, async (c): Promise<SceneOutcome> => {
    const d = await newDeal(c, 'locked');
    const s = await stranger(c);
    const r = await c.attempt(s, d.finishTx({ from: s.classicAddress }));
    const ok = outcome(r) === 'validated:tecNO_PERMISSION';
    return {
      defeated: ok,
      code: r.status === 'expired' ? 'expired' : r.result,
      detail: `a stranger finished the escrow with the right release code: ${outcome(r)}`,
      ...txOf(r),
    };
  });

// Source: DESIGN 5.2 step 5g, T-A-01 (MASTER_DISABLED)
const masterKeyOn = (ws: string) => () =>
  onLedger(ws, async (c): Promise<SceneOutcome> => {
    const d = await newDeal(c, 'credentials'); // everything but 5g: the setup key was not switched off
    const findings = await d.lockCheck();
    const bad = findings.filter((f) => f.level === 'block' && !f.ok);
    return {
      defeated: bad.some((f) => f.code === 'MASTER_DISABLED'),
      code: bad.map((f) => f.code).join(','),
      detail: 'the setup key was left on, so the lock checker refuses the wallet',
      findings,
    };
  });

// Source: https://xrpl.org/docs/references/protocol/transaction-results/tef-codes/ (tefPAST_SEQ), T-A-12, DESIGN D9
const doubleExit = (ws: string) => () =>
  onLedger(ws, async (c): Promise<SceneOutcome> => {
    const d = await newDeal(c, 'locked');
    await d.release();
    const slot = await nextSlot(c.rpc, d.wallet);
    const amount = '1000000';
    const payBob = build8({ shell: d.wallet, payout: d.data.payoutB, amount, slot }, c.ctx);
    const refund = build8({ shell: d.wallet, payout: d.data.payoutA, amount, slot }, c.ctx);
    const first = await c.attemptMulti(payBob, d.slots(), 5);
    const second = await c.attemptMulti(refund, d.slots(), 5);
    return {
      defeated: first.status === 'validated' && second.status === 'rejected' && second.result === 'tefPAST_SEQ',
      code: second.status === 'expired' ? 'expired' : second.result,
      detail: `both exits were signed on slot S: the first is ${outcome(first)}, the second ${outcome(second)}`,
      ...txOf(first),
    };
  });

// ---------- off the ledger ----------

// Source: tools/verifier-cli (task 3.8); the evidence service's own bundle builder
async function bundleByte(): Promise<SceneOutcome> {
  const dir = mkdtempSync(join(tmpdir(), 'legx-attack-'));
  const b = await makeBundle();
  const verify = async (bytes: Uint8Array, name: string) => {
    const path = join(dir, name);
    writeFileSync(path, bytes);
    // the report file in `dir` holds the findings; the last run (the attacked bundle) leaves its own
    return verifyBundle(
      [path, '--out-dir', dir, '--profile', 'demo', '--insecure-unpinned', '--insecure-bundle-tsa-roots'],
      { out: () => undefined, err: () => undefined },
    );
  };
  const control = await verify(b.zip, 'good.zip');
  const bad = new Uint8Array(b.zip);
  const at = bad.length >> 1;
  bad[at] = (bad[at] as number) ^ 1;
  const attacked = await verify(bad, 'bad.zip');
  const failed = readFileSync(join(dir, 'legx-verify-report.json'), 'utf8');
  const first = (
    JSON.parse(failed) as { findings: { check: string; status: string; message: string }[] }
  ).findings.find((f) => f.status === 'fail');
  return {
    defeated: control === 0 && attacked !== 0,
    code: first ? `FAIL:${first.check}` : `exit ${attacked}`,
    detail: `one bit of the bundle changed at byte ${at}; the offline verifier ${attacked === 0 ? 'still passes' : 'fails'}${first ? `: ${first.message}` : ''}`,
  };
}

// Source: ICAO 9303 part 11 5.1 (passive authentication), T-U-16b
async function fakePassport(): Promise<SceneOutcome> {
  const mrz = {
    documentNumber: 'L898902C3',
    surname: 'ERIKSSON',
    givenNames: 'ANNA MARIA',
    dateOfBirth: '740812',
    sex: 'F',
    dateOfExpiry: '340415',
  } as const;
  const seed = new Uint8Array(32).fill(9);
  const pki = makeTestPki({ seed, alg: 'ecdsa-p256' });
  const trustList = [pki.csca.cert];
  const at = Date.parse('2027-06-01T12:00:00Z') / 1000 - 946_684_800;
  const check = (p: { dg1: Uint8Array; sod: Uint8Array; dg14?: Uint8Array; dg15?: Uint8Array }) =>
    passiveAuth({ dg1: p.dg1, sod: p.sod, dg14: p.dg14, dg15: p.dg15, trustList, atTime: at });
  const good = await check(makePassport({ pki, mrz, seed }));
  const fake = await check(makeBadVariants({ pki, mrz, seed }).wrongCsca.passport);
  const code = fake.ok ? 'accepted' : fake.code;
  return {
    defeated: good.ok && !fake.ok,
    code,
    detail: 'a passport whose DS certificate is signed by a rogue CSCA with the same name',
    findings: fake.ok ? [] : [red('PASSPORT_A_OK', code)],
  };
}

// Source: DESIGN 6.17 (BAR_A_OK, BAR_B_OK), T-A-29
async function staleBar(): Promise<SceneOutcome> {
  const w = await makeWorld();
  const i = mutable(w.input);
  i.ledger.history[1].closeTime = NOW - 31 * 86_400; // the bar check is 31 days old; the limit is 30
  const findings = checkRelease(i);
  const bad = findings.filter((f) => !f.ok);
  return {
    defeated: bad.some((f) => f.code === 'BAR_A_OK') && bad.some((f) => f.code === 'BAR_B_OK'),
    code: bad.map((f) => f.code).join(','),
    detail: `the bar verification is 31 days old: ${bad.map((f) => f.detail).join(', ')}`,
    findings,
  };
}

// Source: DESIGN 6.13 (the post-quantum binding), P1.12-09
async function strippedPq(): Promise<SceneOutcome> {
  const w = await makeWorld();
  const i = mutable(w.input);
  const d = w.pqData('B') as { binding: Record<string, unknown> };
  delete d.binding.cross_sig; // the post-quantum cross-signature is cut off
  i.records.pqBound.B = await w.event('pq.bound', d);
  const findings = checkRelease(i);
  const bad = findings.filter((f) => !f.ok);
  return {
    defeated: bad.length === 1 && bad[0]?.code === 'PQ_BINDINGS_OK',
    code: bad[0]?.detail ?? 'accepted',
    detail: 'the post-quantum signature was stripped from a slot binding',
    findings,
  };
}

// Source: DESIGN 6.10 (the release proof binds presenceMsg), T-U-28 replay
async function replayedZk(): Promise<SceneOutcome> {
  const s = zkSet('alice-release');
  const salt = new Uint8Array(32).fill(0x61);
  const presence = (ledgerHash: string) =>
    tupleHash('legx/passport-presence/v1', [
      hex(s.inputs.dealSeal1),
      new TextEncoder().encode('A'),
      hex(ledgerHash),
      hex(s.inputs.lawyerNonce),
    ]);
  // the sealed identity commitment comes from the recorded onboarding result of the same person
  const identifier = zkSet('alice-onboarding').verification.uniqueIdentifier as string;
  const commitment = Buffer.from(zkIdentityCommitment(salt, identifier)).toString('hex');
  const withId = (ledgerHash: string) => ({
    stage: 'release' as const,
    dealId: s.inputs.deal1,
    boundValue: releaseBoundValue(presence(ledgerHash)),
    profile: 'demo' as const,
    faceMatchOptional: true,
    identity: { zkSalt32: salt, commitment },
  });
  const control = checkZkResult(s.verification, s.request.originalQuery, withId(s.inputs.ledgerHash));
  const replay = checkZkResult(s.verification, s.request.originalQuery, withId('77'.repeat(32)));
  const code = replay.ok ? 'accepted' : replay.code;
  return {
    defeated: control.ok && !replay.ok && replay.code === 'BOUND_VALUE_MISMATCH',
    code,
    detail: 'a release proof recorded for an earlier ledger hash was presented again',
    findings: replay.ok ? [] : [red('PASSPORT_A_OK', code)],
  };
}

// Source: https://www.rfc-editor.org/rfc/rfc9591#section-5.2 ; DESIGN 6.4
async function foreignShare(): Promise<SceneOutcome> {
  const slotA = await dkgKeys('A');
  const slotB = await dkgKeys('B');
  const msg = new TextEncoder().encode('exit transaction');
  const own = SigningSession.open(slotA.keys[0]?.secret as never, slotA.pub, msg);
  let code = 'accepted';
  try {
    SigningSession.open(slotB.keys[0]?.secret as never, slotA.pub, msg); // a share of another slot, offered to slot A
  } catch (e) {
    code = (e as { code?: string }).code ?? (e as Error).message;
  }
  return {
    defeated: code === 'SHARE_INVALID' && own.commitment !== undefined,
    code,
    detail: 'a FROST share from outside the slot was offered to the signing session',
  };
}

/** The scenes for a demo server whose standalone ledger listens at `ledgerWs`. */
export function realScenes(ledgerWs: string): Scenes {
  return {
    'stranger-finish': strangerFinish(ledgerWs),
    'master-key-on': masterKeyOn(ledgerWs),
    'double-exit': doubleExit(ledgerWs),
    'bundle-byte': bundleByte,
    'fake-passport': fakePassport,
    'stale-bar': staleBar,
    'stripped-pq': strippedPq,
    'replayed-zk': replayedZk,
    'foreign-share': foreignShare,
  };
}
