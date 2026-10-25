// Object keys are `/`-separated names of ASCII letters, digits and `._-`: no `..`, no empty segment, no leading `/`.
// Both stores take keys from internal code, but a key can include a deal ID or a hash from outside.
const SEGMENT = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/;

export function assertKey(key: string): void {
  const parts = key.split('/');
  if (key.length > 512 || parts.some((p) => !SEGMENT.test(p) || p === '..'))
    throw new RangeError(`invalid object key: ${key.slice(0, 80)}`);
}
