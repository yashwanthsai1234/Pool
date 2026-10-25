import { sha256 } from '@noble/hashes/sha2.js';

/** The fixed inputs of the recorded TSA exchanges (scripts/record-tsa.ts). */
export const FIXTURE_HASH = sha256(new TextEncoder().encode('legx evidence service TSA fixture v1'));
export const FIXTURE_NONCE = Uint8Array.from([0x2a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
