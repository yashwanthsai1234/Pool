// Regenerates passport-vector.json (Node only): node packages/core/test/browser/gen-passport-vector.ts
import { writeFileSync } from 'node:fs';
import { chipAnswerAA, makePassport, makeTestPki } from '@legx/fixtures';
import { bytesToHex } from '@noble/hashes/utils.js';

const seed = new Uint8Array(32).fill(9);
const mrz = {
  documentNumber: 'L898902C3',
  surname: 'ERIKSSON',
  givenNames: 'ANNA MARIA',
  dateOfBirth: '740812',
  sex: 'F',
  dateOfExpiry: '340415',
} as const;
const challenge = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
const out: Record<string, Record<string, string>> = {};
for (const alg of ['ecdsa-p256', 'rsa-pss'] as const) {
  const pki = makeTestPki({ seed, alg });
  const p = makePassport({ pki, mrz, seed, aa: 'rsa' });
  out[alg] = {
    dg1: bytesToHex(p.dg1),
    sod: bytesToHex(p.sod),
    dg14: p.dg14 ? bytesToHex(p.dg14) : '',
    dg15: bytesToHex(p.dg15),
    csca: bytesToHex(pki.csca.cert),
    challenge: bytesToHex(challenge),
    signature: bytesToHex(chipAnswerAA(p.aaKey, challenge)),
  };
}
writeFileSync(new URL('./passport-vector.json', import.meta.url), `${JSON.stringify(out, null, 1)}\n`);
