// P3.10-13: the firm's signed key list and its ledger anchor (T-U-29 at service level).
import { bytesToHex } from '@legx/core/dealcore';
import type { Role } from '@legx/core/frost';
import { toBase64 } from '@legx/core/pq';
import { describe, expect, it } from 'vitest';
import { ECDSA, Wallet } from 'xrpl';
import { type Member, makeMember } from '../../recovery-agent/test/support/world.ts';
import { acceptServiceKey, anchorMemo, buildFirmKeyList, readAnchor, signKeyList } from '../src/keylist.ts';

const ops = Wallet.generate(ECDSA.ed25519);
const secretOf = (w: Wallet) => new Uint8Array(Buffer.from(w.privateKey.slice(2), 'hex'));
const firm = [makeMember(1, 'LA', 'console'), makeMember(2, 'LA', 'firm-hsm'), makeMember(3, 'LA', 'partner')];
const entry = (m: Member) => ({ holder: m.keys.keyId, role: m.info.role as Role, edPub: m.info.edPub });
const listOf = (members: Member[], by = ops) =>
  signKeyList(
    buildFirmKeyList(
      members.map((m) => ({
        holder: m.keys.keyId,
        role: m.info.role as 'console' | 'firm-hsm' | 'partner',
        ed25519: `ED${bytesToHex(m.info.edPub.slice(1)).toUpperCase()}`,
        mldsa65: toBase64(m.info.pqPub),
      })),
    ),
    secretOf(by),
  );
const ledgerWith = (account: string, memoOf: Uint8Array | undefined) =>
  ({
    tx: async () => ({
      tx: { Account: account, TransactionType: 'AccountSet', ...(memoOf ? { Memos: [anchorMemo(memoOf)] } : {}) },
      meta: { TransactionResult: 'tesSUCCESS' },
    }),
  }) as never;
const anchorOf = (list: { bytes: Uint8Array }, account = ops.classicAddress) =>
  readAnchor(ledgerWith(account, list.bytes), 'AA'.repeat(32));

describe('P3.10-13 the firm key list', () => {
  it('the console accepts the HSM, console and partner keys when the anchor is the list hash from the operations account', async () => {
    const list = listOf(firm);
    const anchor = await anchorOf(list);
    for (const m of firm)
      expect(acceptServiceKey({ list, anchor, agentAccount: ops.classicAddress, key: entry(m) }).role).toBe(
        m.info.role,
      );
  });

  it('refuses a list signed by another account, a swapped list, a missing anchor, an anchor from another account, and a key not listed', async () => {
    const list = listOf(firm);
    const anchor = await anchorOf(list);
    const other = Wallet.generate(ECDSA.ed25519);
    const key = entry(firm[1] as Member);
    const accept = (over: Partial<Parameters<typeof acceptServiceKey>[0]>) =>
      acceptServiceKey({ list, anchor, agentAccount: ops.classicAddress, key, ...over });
    expect(() => accept({ list: listOf(firm, other) })).toThrow(/PIN_MISMATCH|LIST_SIGNER_WRONG/);
    const forged = signKeyList(list.bytes, secretOf(other));
    expect(() => accept({ list: forged })).toThrow(/LIST_SIGNER_WRONG/);
    const evil = makeMember(2, 'LA', 'firm-hsm');
    expect(() => accept({ list: listOf([firm[0] as Member, evil, firm[2] as Member]) })).toThrow(/PIN_MISMATCH/);
    expect(() => accept({ anchor: undefined })).toThrow(/PIN_MISMATCH/);
    expect(() => accept({ anchor: undefined, list: listOf(firm) })).toThrow(/PIN_MISMATCH/);
    expect(() => accept({ anchor: { ...(anchor as object), account: other.classicAddress } as never })).toThrow(
      /PIN_MISMATCH/,
    );
    expect(() => accept({ key: entry(evil) })).toThrow(/KEY_NOT_PINNED/);
  });
});
