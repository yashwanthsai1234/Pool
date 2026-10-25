// UUIDv7: 48-bit millisecond time, version 7, variant 10, random rest. Source: https://www.rfc-editor.org/rfc/rfc9562.html#name-uuid-version-7
import { randomBytes } from 'node:crypto';

export function uuid7(): string {
  const b = randomBytes(16);
  b.writeUIntBE(Date.now(), 0, 6);
  b[6] = ((b[6] as number) & 0x0f) | 0x70;
  b[8] = ((b[8] as number) & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
