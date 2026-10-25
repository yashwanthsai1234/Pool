// E2E-P1 helper: the public bundle an arbitrator receives is plain JSON. Byte strings travel as {"$hex": "..."}, so the
// recomputation cannot lean on any in-memory object of the run that made the deal.
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

export const toBundle = (x: unknown): unknown =>
  JSON.parse(JSON.stringify(x, (_k, v) => (v instanceof Uint8Array ? { $hex: bytesToHex(v) } : v)));

export const fromBundle = (x: unknown): unknown =>
  JSON.parse(JSON.stringify(x), (_k, v) =>
    v !== null && typeof v === 'object' && '$hex' in v && Object.keys(v).length === 1 ? hexToBytes(String(v.$hex)) : v,
  );
