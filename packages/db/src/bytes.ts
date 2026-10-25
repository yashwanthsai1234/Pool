// Hex at the API (contracts use lowercase hex strings), bytea in the tables.
/** A plain Uint8Array: `pg` returns a Buffer for bytea and PGlite a Uint8Array, and callers must see one type. */
export const bytes = (b: Uint8Array): Uint8Array => new Uint8Array(b);
export const bin = (h: string): Buffer => Buffer.from(h, 'hex');
export const hex = (b: Uint8Array): string => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString('hex');
export const hexOrNull = (b: Uint8Array | null): string | null => (b === null ? null : hex(b));
export const binOrNull = (h: string | null | undefined): Buffer | null => (h == null ? null : bin(h));

/** Postgres SQLSTATE 23505, optionally for one named constraint. Source: https://www.postgresql.org/docs/18/errcodes-appendix.html */
export function isUniqueViolation(e: unknown, constraint?: string): boolean {
  const err = e as { code?: string; constraint?: string } | null;
  return err?.code === '23505' && (constraint === undefined || err.constraint === constraint);
}
