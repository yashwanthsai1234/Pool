// Test-only: @legx/fixtures (the fixture passports of the demo profile) uses two Node Buffer helpers. The console itself
// is Buffer-free (OD-27); this shim only lets the fixtures run in a browser test.
const compare = (a: Uint8Array, b: Uint8Array): number => {
  for (let i = 0; i < Math.min(a.length, b.length); i++)
    if (a[i] !== b[i]) return (a[i] as number) < (b[i] as number) ? -1 : 1;
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
};
const from = (b: Uint8Array) => ({
  toString: (_enc: 'hex') => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''),
});
// a function, not a plain object: the test runner does `x instanceof Buffer` when it reports an error
(globalThis as { Buffer?: unknown }).Buffer ??= Object.assign(function Buffer() {}, { compare, from });
