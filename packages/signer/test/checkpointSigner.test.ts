// CheckpointSignerPort contract: Ed25519 over the note body, ML-DSA-44 over the CosignedSubtree with the empty context.

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CheckpointSignerPort } from '@legx/contracts/ports';
import type { KeyId } from '@legx/contracts/values';
import { mldsaVerify } from '@legx/core/pq';
import { cosignedSubtree } from '@legx/core/pqCheckpoint';
import { verifyXrplKeySig } from '@legx/core/verify';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { fileCheckpointSigner, generateNodeCheckpointKeys, nodeCheckpointSigner } from '../src/index.ts';

const impls: [string, () => CheckpointSignerPort][] = [
  [
    'NodeSigner (checkpoint)',
    () => nodeCheckpointSigner(generateNodeCheckpointKeys('log-ed' as KeyId, 'log-pq' as KeyId)),
  ],
  [
    'FileSigner (checkpoint)',
    () => fileCheckpointSigner(join(mkdtempSync(join(tmpdir(), 'legx-cp-')), 'log.json'), { LEGX_PROFILE: 'demo' }),
  ],
];

describe.each(impls)('CheckpointSignerPort contract: %s', (_name, make) => {
  const noteBody = new TextEncoder().encode('legx.example/log\n3\n'.concat('A'.repeat(43), '=\n'));
  const subtree = cosignedSubtree(
    'legx.example/log+pq',
    1_700_000_000n,
    'legx.example/log',
    0n,
    3n,
    new Uint8Array(32).fill(9),
  );

  it('returns both signatures of the documented sizes; both verify', async () => {
    const s = make();
    const pub = await s.publicKeys();
    expect(pub.ed25519).toHaveLength(32);
    expect(pub.mlDsa44).toHaveLength(1312);
    const sig = await s.signCheckpoint({ noteBody, cosignedSubtree: subtree });
    expect(sig.ed25519).toHaveLength(64);
    expect(sig.mlDsa44).toHaveLength(2420);
    expect(sig.keyIds).toEqual(pub.keyIds);
    expect(verifyXrplKeySig(`ED${bytesToHex(pub.ed25519)}`, noteBody, bytesToHex(sig.ed25519))).toBe(true);
    expect(mldsaVerify('ml-dsa-44', pub.mlDsa44, subtree, sig.mlDsa44, '')).toBe(true);
  });

  it('signs ML-DSA-44 under the empty context only', async () => {
    const s = make();
    const pub = await s.publicKeys();
    const sig = await s.signCheckpoint({ noteBody, cosignedSubtree: subtree });
    expect(mldsaVerify('ml-dsa-44', pub.mlDsa44, subtree, sig.mlDsa44, 'legx/checkpoint/v1')).toBe(false);
  });

  it('does not let one half stand for the other: the Ed25519 line does not cover the subtree', async () => {
    const s = make();
    const pub = await s.publicKeys();
    const sig = await s.signCheckpoint({ noteBody, cosignedSubtree: subtree });
    expect(verifyXrplKeySig(`ED${bytesToHex(pub.ed25519)}`, subtree, bytesToHex(sig.ed25519))).toBe(false);
  });
});
