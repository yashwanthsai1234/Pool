// Makes the cross-language test vector for the iOS app from the real @legx/chip-link code, and (with `open`) opens
// a bundle that the Swift tests sealed. Run: node tools/gen-vector.ts  |  node tools/gen-vector.ts open <file>
// Source: packages/chip-link/src/{wire,channel}.ts
import { readFileSync, writeFileSync } from 'node:fs';
import { bytesToHex, hexToBytes } from '../../../packages/chip-link/node_modules/@noble/hashes/utils.js';
import {
  createSession,
  decodeChipData,
  encodeChipData,
  openSealed,
  parseQr,
  sealToQr,
} from '../../../packages/chip-link/src/index.ts';

const hex = bytesToHex;
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);

if (process.argv[2] === 'open') {
  const j = JSON.parse(readFileSync(process.argv[3] as string, 'utf8'));
  const s = await createSession(new Uint8Array(32)); // only to get a Session shape; replaced below
  const session = {
    ...s,
    qr: j.qr,
    sessionId: hexToBytes(j.sessionId),
    challenge: hexToBytes(j.challenge),
    secretKey: hexToBytes(j.secretKey),
  };
  const r = await openSealed(session, { enc: hexToBytes(j.enc), ct: hexToBytes(j.ct) });
  if (!r.ok) throw new Error(`open failed ${r.code}`);
  const d = decodeChipData(r.plaintext);
  if (!d.ok) throw new Error(`decode failed ${d.code}`);
  if (hex(r.plaintext) !== j.plaintext) throw new Error('plaintext mismatch');
  console.log('Swift-sealed bundle opened by @legx/chip-link: OK, dg1 bytes =', d.data.dg1.length);
} else {
  const presenceMsg = fill(32, 7);
  const s = await createSession(presenceMsg);
  const data = { dg1: fill(93, 1), sod: fill(300, 2), dg14: fill(40, 3), dg15: fill(90, 4), aaSignature: fill(128, 5) };
  const plaintext = encodeChipData(data);
  const qr = parseQr(s.qr);
  if (!qr) throw new Error('qr');
  const sealed = await sealToQr(qr, plaintext);
  const vec = {
    qr: s.qr,
    sessionId: hex(s.sessionId),
    challenge: hex(s.challenge),
    secretKey: hex(s.secretKey),
    wireOnlyDg1Sod: hex(encodeChipData({ dg1: fill(3, 9), sod: fill(2, 8) })),
    plaintext: hex(plaintext),
    enc: hex(sealed.enc),
    ct: hex(sealed.ct),
    fields: {
      dg1: hex(data.dg1),
      sod: hex(data.sod),
      dg14: hex(data.dg14),
      dg15: hex(data.dg15),
      aa: hex(data.aaSignature),
    },
  };
  writeFileSync(new URL('../Tests/vector.json', import.meta.url), JSON.stringify(vec, null, 1));
  console.log('vector written; sk bytes', s.secretKey.length, 'enc', sealed.enc.length);
}
