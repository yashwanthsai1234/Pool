// The chip-link transfer format: DG1, EF.SOD, DG14, DG15 and the Active Authentication answer in one message.
// Layout: "LGXC" || version(1) || fields, each field = tag(1) || length(4, big endian) || value.
// Tags ascend, none repeats, DG1 and SOD are required, nothing may trail. The Kotlin app writes the same bytes.
// Source: DESIGN.md 6.15 (the helper sends DG1, EF.SOD, DG14, DG15 and the AA answer)
import { concatBytes } from '@noble/hashes/utils.js';

export interface ChipData {
  readonly dg1: Uint8Array;
  readonly sod: Uint8Array;
  readonly dg14?: Uint8Array | undefined;
  readonly dg15?: Uint8Array | undefined;
  /** The chip's INTERNAL AUTHENTICATE answer to the 8-byte challenge. */
  readonly aaSignature?: Uint8Array | undefined;
}

export type WireCode =
  | 'WIRE_MAGIC'
  | 'WIRE_VERSION'
  | 'WIRE_TRUNCATED'
  | 'WIRE_TAG'
  | 'WIRE_TOO_LARGE'
  | 'WIRE_MISSING';
export type Decoded = { readonly ok: true; readonly data: ChipData } | { readonly ok: false; readonly code: WireCode };

const MAGIC = Uint8Array.of(0x4c, 0x47, 0x58, 0x43);
export const WIRE_VERSION = 1;
/** A passport's DG15 and SOD are a few KB; 1 MiB per field and in total is far above any real chip file. */
export const MAX_FIELD = 1 << 20;
const FIELDS = [
  ['dg1', 1],
  ['sod', 2],
  ['dg14', 3],
  ['dg15', 4],
  ['aaSignature', 5],
] as const;

const be32 = (n: number) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);

export function encodeChipData(d: ChipData): Uint8Array {
  const parts: Uint8Array[] = [MAGIC, Uint8Array.of(WIRE_VERSION)];
  for (const [name, tag] of FIELDS) {
    const v = d[name];
    if (v === undefined) continue;
    if (v.length > MAX_FIELD) throw new RangeError('WIRE_TOO_LARGE');
    parts.push(Uint8Array.of(tag), be32(v.length), v);
  }
  return concatBytes(...parts);
}

/** Never throws: any byte string gives either the data or one code. */
export function decodeChipData(b: Uint8Array): Decoded {
  const fail = (code: WireCode): Decoded => ({ ok: false, code });
  if (b.length < 5) return fail(b.length < MAGIC.length ? 'WIRE_TRUNCATED' : 'WIRE_MAGIC');
  if (!MAGIC.every((x, i) => b[i] === x)) return fail('WIRE_MAGIC');
  if (b[4] !== WIRE_VERSION) return fail('WIRE_VERSION');
  const out: Record<string, Uint8Array> = {};
  let pos = 5;
  let last = 0;
  while (pos < b.length) {
    if (pos + 5 > b.length) return fail('WIRE_TRUNCATED');
    const tag = b[pos] as number;
    const len =
      (b[pos + 1] as number) * 2 ** 24 +
      ((b[pos + 2] as number) << 16) +
      ((b[pos + 3] as number) << 8) +
      (b[pos + 4] as number);
    const name = FIELDS.find(([, t]) => t === tag)?.[0];
    if (name === undefined || tag <= last) return fail('WIRE_TAG');
    if (len > MAX_FIELD) return fail('WIRE_TOO_LARGE');
    pos += 5;
    if (pos + len > b.length) return fail('WIRE_TRUNCATED');
    out[name] = b.slice(pos, pos + len);
    pos += len;
    last = tag;
  }
  if (!out.dg1 || !out.sod) return fail('WIRE_MISSING');
  return {
    ok: true,
    data: { dg1: out.dg1, sod: out.sod, dg14: out.dg14, dg15: out.dg15, aaSignature: out.aaSignature },
  };
}
