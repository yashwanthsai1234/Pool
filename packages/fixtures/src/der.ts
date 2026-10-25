/**
 * One DER TLV with a definite length (short form below 128, long form above).
 * Source: https://www.itu.int/rec/T-REC-X.690 (8.1.3, 10.1)
 */
export function tlv(tag: readonly number[], value: Uint8Array): Uint8Array<ArrayBuffer> {
  const n = value.length;
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : undefined;
  if (!len) throw new RangeError('value too long for a fixture TLV');
  const out = new Uint8Array(tag.length + len.length + n);
  out.set(tag);
  out.set(len, tag.length);
  out.set(value, tag.length + len.length);
  return out;
}

/** DER SET OF: the elements sorted by their encodings. Source: https://www.itu.int/rec/T-REC-X.690 (11.6) */
export function derSetOf(elements: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const sorted = [...elements].sort((a, b) => Buffer.compare(a, b));
  return tlv([0x31], Uint8Array.from(sorted.flatMap((e) => [...e])));
}
