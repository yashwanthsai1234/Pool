// P4.4-03, 04, 05, 13, 14: the passport check is method-aware, the attestation is signed only after the client's
// presence signature verifies, the passport data is dropped afterwards, and a failed face match cannot be signed.
import './buffer-shim.ts';
import { createSession, simSend } from '@legx/chip-link';
import type { ZkVerification } from '@legx/contracts/records';
import { bytesToHex, hexToBytes, passportCommitment, sha256, utf8ToBytes } from '@legx/core/dealcore';
import { aaChallenge } from '@legx/core/passport/activeAuth';
import { passportRecord } from '@legx/core/passport/passiveAuth';
import { releaseBoundValue, zkIdentityCommitment, zkScope } from '@legx/core/zkIdentity';
import { chipAnswerAA, makePassport, makeTestPki } from '@legx/fixtures';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { DEAL_ID, h32 } from '../../../../packages/core/test/helpers/gate.ts';
import { LEDGER, makeConsole, mutable, world } from './harness.ts';

vi.setConfig({ testTimeout: 60_000, hookTimeout: 120_000 });
beforeAll(async () => void (await world()));

const SALT = new Uint8Array(32).fill(0x5a);
const TRUST = {
  chainId: 1,
  blockNumber: 21_000_000,
  blockHash: `0x${h32(0x0b)}`,
  registryAddress: `0x${'ab'.repeat(20)}`,
  root: `0x${h32(0x0c)}`,
  circuitManifestVersion: '0.40.1',
  vkeyHashes: [`0x${h32(0x0d)}`],
  devMode: false,
};

/** A zero-knowledge adapter fake whose result can be bent. */
function zkAdapter(
  over: {
    errors?: ZkVerification['queryResultErrors'];
    facematch?: 'strict' | 'none';
    identifier?: string;
    bound?: string;
  } = {},
) {
  // I-S-G3: the stored set must carry this deal's scopes in its public inputs and bind the presence message.
  const field = (str: string) => `00${bytesToHex(sha256(utf8ToBytes(str)).slice(0, 31))}`;
  let proofSet: Uint8Array<ArrayBuffer> = new Uint8Array();
  const remember = (set: Uint8Array<ArrayBuffer>) => {
    proofSet = set;
    return set;
  };
  const setFor = (msg: Uint8Array) =>
    utf8ToBytes(
      JSON.stringify([
        {
          name: 'public proof set A',
          proof: `${h32(1)}${h32(2)}${field('legx.app')}${field(zkScope(DEAL_ID))}${'ab'.repeat(64)}`,
          committedInputs: { bind: { data: { custom_data: bytesToHex(msg) } } },
        },
      ]),
    );
  return {
    salt: async () => SALT,
    trustList: [] as Uint8Array[],
    zkRequest: (msg: Uint8Array) => ({
      proofSet: remember(setFor(msg)),
      request: {
        stage: 'release',
        domain: 'legx.app',
        scope: zkScope(DEAL_ID),
        devMode: false,
        proofs: [],
        originalQuery: {
          bind: { custom_data: releaseBoundValue(msg) },
          facematch: { mode: over.facematch ?? 'strict' },
        },
        queryResult: {},
      } as never,
    }),
    zkVerify: async (req: { originalQuery: Record<string, unknown> }): Promise<ZkVerification> => ({
      verified: true,
      uniqueIdentifier: over.identifier ?? 'ID-A',
      uniqueIdentifierType: 'SALTED',
      queryResultErrors: over.errors ?? {},
      proofSha256: bytesToHex(sha256(proofSet)) as never,
      vkeyHash: `0x${h32(0x0e)}` as never,
      version: '0.40.1',
      committedInputs: { custom_data: over.bound ?? (req.originalQuery.bind as { custom_data: string }).custom_data },
      scope: zkScope(DEAL_ID),
      domain: 'legx.app',
      trust: TRUST as never,
    }),
  };
}

const zkWorld = async (over: Parameters<typeof zkAdapter>[0] = {}, policy?: string) => {
  const w = await world();
  const data = {
    ...w.input.deal.data,
    commitmentA: bytesToHex(zkIdentityCommitment(SALT, 'ID-A')),
    ...(policy ? { identityPolicy: policy } : {}),
  };
  const x = await makeConsole({ role: 'LA', data: data as never, identity: zkAdapter(over) });
  return { ...x, w, data };
};
const presenceSig = (w: Awaited<ReturnType<typeof world>>, side: 'A' | 'B', hex: string) =>
  w.S[side].sign(hexToBytes(hex));

describe('P4.4-03 and P4.4-04: the zero-knowledge method (default)', () => {
  it('shows each proof check as PASS; signing waits for the client presence signature, then signs and records', async () => {
    const { c, w, spies } = await zkWorld();
    const begun = await c.passport.begin();
    expect(begun.presenceMsgHex).toMatch(/^[0-9a-f]{64}$/);
    const checked = await c.passport.check();
    expect(checked.method).toBe('zkpassport');
    expect(checked.items.map((i) => [i.name, i.status])).toEqual([
      ['proof_verified', 'pass'],
      ['identifier_matches', 'pass'],
      ['bound_value_is_presence_msg', 'pass'],
      ['document_not_expired', 'pass'],
      ['face_match_passed', 'pass'],
    ]);
    // P4.4-04: without the presence signature the sign button stays off
    expect(checked.canSign).toBe(false);
    expect(checked.blocked).toContain('presence signature');
    await expect(c.passport.sign()).rejects.toMatchObject({ code: 'NOT_READY' });
    expect(spies.appended).toHaveLength(0);
    // a signature by the wrong key, or over another message, does not count
    expect(c.passport.submitPresence(w.S.B.sign(hexToBytes(begun.presenceMsgHex as string))).presence).toBe('invalid');
    expect(c.passport.submitPresence(presenceSig(w, 'A', '00'.repeat(32))).presence).toBe('invalid');
    expect(c.passport.state().canSign).toBe(false);
    expect(c.passport.submitPresence(new Uint8Array(10)).presence).toBe('invalid');
    // the right one
    const ready = c.passport.submitPresence(presenceSig(w, 'A', begun.presenceMsgHex as string));
    expect(ready.presence).toBe('valid');
    expect(ready.canSign).toBe(true);
    const bytes = await c.passport.sign();
    expect(c.passport.state().phase).toBe('signed');
    expect(spies.appended).toHaveLength(1);
    expect(JSON.parse(new TextDecoder().decode(bytes)).payloadType).toBe('application/vnd.legx.attest+json;v=1');
    expect(spies.evidence.attach).toHaveBeenCalledWith('zk-proof', 'A', expect.any(Uint8Array));
  });

  it('a nonce is single use: a second check makes a new presence message', async () => {
    const { c } = await zkWorld();
    const a = (await c.passport.begin()).presenceMsgHex;
    const b = (await c.passport.begin()).presenceMsgHex;
    expect(a).not.toBe(b);
  });

  it('a signed attestation cannot be signed twice', async () => {
    const { c, w } = await zkWorld();
    const b = await c.passport.begin();
    await c.passport.check();
    c.passport.submitPresence(presenceSig(w, 'A', b.presenceMsgHex as string));
    await c.passport.sign();
    await expect(c.passport.sign()).rejects.toMatchObject({ code: 'NOT_READY' });
  });

  it('a proof bound to another message or another identity fails with its own reason', async () => {
    const bound = await zkWorld({ bound: 'beef' });
    await bound.c.passport.begin();
    const s1 = await bound.c.passport.check();
    expect(s1.items.find((i) => i.name === 'bound_value_is_presence_msg')?.status).toBe('fail');
    const id = await zkWorld({ identifier: 'ID-OTHER' });
    await id.c.passport.begin();
    expect((await id.c.passport.check()).items.find((i) => i.name === 'identifier_matches')?.status).toBe('fail');
  });

  it('P4.4-13: a deal whose seal does not allow its own method is refused at the start (dealSeal), so nothing is checked or signed', async () => {
    const { c, spies } = await zkWorld({}, 'chip');
    await expect(c.passport.begin()).rejects.toThrow('not allowed by chip');
    expect(spies.slot.sign).not.toHaveBeenCalled();
  });
});

describe('P4.4-14 the face match', () => {
  it('a proof with a face match error shows FAIL "face match" and the attestation cannot be signed', async () => {
    const { c, w } = await zkWorld({ errors: { facematch: { mode: 'face match failed' } } });
    const b = await c.passport.begin();
    const s = await c.passport.check();
    const item = s.items.find((i) => i.name === 'face_match_passed');
    expect(item).toEqual({ name: 'face_match_passed', status: 'fail', reason: 'face match' });
    c.passport.submitPresence(presenceSig(w, 'A', b.presenceMsgHex as string));
    expect(c.passport.state().canSign).toBe(false);
    await expect(c.passport.sign()).rejects.toMatchObject({ code: 'NOT_READY' });
  });

  it('a proof made from copied chip data has no strict face match in its query: FAIL "face match"', async () => {
    const { c, w, spies } = await zkWorld({ facematch: 'none' });
    const b = await c.passport.begin();
    const s = await c.passport.check();
    expect(s.items.find((i) => i.name === 'face_match_passed')).toMatchObject({ status: 'fail', reason: 'face match' });
    c.passport.submitPresence(presenceSig(w, 'A', b.presenceMsgHex as string));
    await expect(c.passport.sign()).rejects.toMatchObject({ code: 'NOT_READY' });
    expect(spies.appended).toHaveLength(0);
  });
});

// ---------- the chip method (fallback) ----------

const RIPPLE_EPOCH = 946_684_800;
const AT = Date.parse('2027-06-01T12:00:00Z') / 1000 - RIPPLE_EPOCH;
const MRZ = {
  documentNumber: 'L898902C3',
  surname: 'ERIKSSON',
  givenNames: 'ANNA MARIA',
  dateOfBirth: '740812',
  sex: 'F',
  dateOfExpiry: '340415',
} as const;
const seed = new Uint8Array(32).fill(9);
const pki = makeTestPki({ seed });
const good = makePassport({ pki, mrz: MRZ, seed });

async function chipWorld(trusted = true) {
  const w = await world();
  const input = mutable(w.input);
  input.ledger.closeTime = AT;
  const commitment = bytesToHex(passportCommitment(passportRecord(good.dg1, good.sod), SALT));
  const data = { ...input.deal.data, commitmentB: commitment };
  const x = await makeConsole({
    role: 'LB',
    input,
    data: data as never,
    now: AT,
    identity: { salt: async () => SALT, trustList: trusted ? [pki.csca.cert] : [] },
  });
  return { ...x, w };
}

describe('P4.4-03 the chip method', () => {
  it('through the reader helper: runs passiveAuth in the console and shows each check as PASS', async () => {
    const { c, w, spies } = await chipWorld();
    const b = await c.passport.begin();
    expect(b.qr).toMatch(/^legxchip1:/);
    const sealed = await simSend(b.qr as string, { passport: good, aaKey: good.aaKey });
    const s = await c.passport.check({ kind: 'reader', sealed });
    expect(s.items.map((i) => i.name)).toEqual([
      'sod_signature_valid',
      'ds_cert_chains_to_csca',
      'dg1_hash_in_sod',
      'document_not_expired',
      'commitment_opens',
      'chip_authentication',
    ]);
    expect(s.items.every((i) => i.status === 'pass')).toBe(true);
    c.passport.submitPresence(presenceSig(w, 'B', b.presenceMsgHex as string));
    await c.passport.sign();
    expect(spies.appended).toHaveLength(1);
  });

  it('an untrusted issuer fails ds_cert_chains_to_csca, the checks after it are not reached, and nothing can be signed', async () => {
    const { c, w } = await chipWorld(false);
    const b = await c.passport.begin();
    const sealed = await simSend(b.qr as string, { passport: good, aaKey: good.aaKey });
    const s = await c.passport.check({ kind: 'reader', sealed });
    const status = Object.fromEntries(s.items.map((i) => [i.name, i.status]));
    expect(status.sod_signature_valid).toBe('pass');
    expect(status.ds_cert_chains_to_csca).toBe('fail');
    expect(status.commitment_opens).toBe('pending');
    for (const i of s.items) expect(['pass', 'fail', 'pending']).toContain(i.status);
    c.passport.submitPresence(presenceSig(w, 'B', b.presenceMsgHex as string));
    expect(c.passport.state().canSign).toBe(false);
  });

  it('a cloned chip (files without the AA key) fails chip_authentication', async () => {
    const { c } = await chipWorld();
    const b = await c.passport.begin();
    const sealed = await simSend(b.qr as string, { passport: good });
    const s = await c.passport.check({ kind: 'reader', sealed });
    expect(s.items.find((i) => i.name === 'chip_authentication')?.status).toBe('fail');
  });

  it('a transfer without a session, or without chip data, is refused', async () => {
    const { c } = await chipWorld();
    await expect(c.passport.check()).rejects.toMatchObject({ code: 'NOT_STARTED' });
    await c.passport.begin();
    await expect(c.passport.check()).rejects.toMatchObject({ code: 'NO_CHIP_DATA' });
    void createSession;
  });
});

/** Does any stored value in any IndexedDB of this origin contain `needle`? */
async function idbContains(needle: Uint8Array): Promise<boolean> {
  const hit = (v: unknown, seen = new Set<unknown>()): boolean => {
    if (v instanceof ArrayBuffer) v = new Uint8Array(v);
    if (ArrayBuffer.isView(v)) {
      const b = new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
      const hay = bytesToHex(b);
      return hay.includes(bytesToHex(needle));
    }
    if (typeof v === 'string') return v.includes(bytesToHex(needle));
    if (v && typeof v === 'object' && !seen.has(v)) {
      seen.add(v);
      return Object.values(v).some((x) => hit(x, seen));
    }
    return false;
  };
  for (const { name } of await indexedDB.databases()) {
    if (!name) continue;
    const db = await new Promise<IDBDatabase>((res, rej) => {
      const r = indexedDB.open(name);
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    for (const store of Array.from(db.objectStoreNames)) {
      const rows = await new Promise<unknown[]>((res, rej) => {
        const r = db.transaction(store).objectStore(store).getAll();
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(r.error);
      });
      if (rows.some((row) => hit(row))) return true;
    }
    db.close();
  }
  return false;
}

describe('P4.4-05 the console drops the passport data after signing', () => {
  it('chip: no DG1 or SOD byte remains in app state or IndexedDB, and the arrays are wiped', async () => {
    const { c, w } = await chipWorld();
    const b = await c.passport.begin();
    const dg1 = good.dg1.slice();
    const sod = good.sod.slice();
    const data = {
      dg1: good.dg1.slice(),
      sod: good.sod.slice(),
      dg14: good.dg14?.slice(),
      dg15: good.dg15?.slice(),
      aaSignature: chipAnswerAA(good.aaKey, aaChallenge(hexToBytes(b.presenceMsgHex as string))),
    };
    await c.passport.check({ kind: 'fixture', data });
    expect(c.passport.state().items.every((i) => i.status === 'pass')).toBe(true);
    c.passport.submitPresence(presenceSig(w, 'B', b.presenceMsgHex as string));
    await c.passport.sign();
    expect(data.dg1.every((x) => x === 0)).toBe(true);
    expect(data.sod.every((x) => x === 0)).toBe(true);
    const state = JSON.stringify(c.passport.state());
    expect(state).not.toContain(bytesToHex(dg1.slice(0, 16)));
    expect(state).not.toMatch(/"(dg1|sod|dg14|dg15)":/);
    expect(c.passport.state().qr).toBeUndefined();
    expect(await idbContains(dg1.slice(0, 24))).toBe(false);
    expect(await idbContains(sod.slice(0, 24))).toBe(false);
  });

  it('zero-knowledge: the proof payload is wiped after the attachment is stored', async () => {
    const { c, w, spies } = await zkWorld();
    let kept: Uint8Array | undefined;
    spies.evidence.attach.mockImplementation(async (_k?: string, _s?: string, bytes?: Uint8Array) => {
      kept = bytes;
    });
    const b = await c.passport.begin();
    await c.passport.check();
    c.passport.submitPresence(presenceSig(w, 'A', b.presenceMsgHex as string));
    await c.passport.sign();
    expect(kept?.every((x) => x === 0)).toBe(true);
    expect(JSON.stringify(c.passport.state())).not.toContain('public proof set');
  });
});

void LEDGER;
