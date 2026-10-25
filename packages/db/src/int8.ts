/** int8 arrives as a string in `pg` and as a bigint-capable value in PGlite. Every int8 in the schema is a ledger index, a seq or a size, so a safe number is enough. */
export function toSafeNumber(v: string): number {
  const n = Number(v);
  if (!Number.isSafeInteger(n)) throw new RangeError(`int8 out of the safe integer range: ${v}`);
  return n;
}
