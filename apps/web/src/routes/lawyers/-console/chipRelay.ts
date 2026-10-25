// The console's end of the chip relay (apps/server/src/chipLink.ts): announces the session shown in the QR code, then
// polls for the phone's sealed bundle. Only ciphertext passes through; `receiveChip` opens it with the one-time key.
// Source: https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API
import { parseQr, type Sealed } from '@legx/chip-link';
import { bytesToHex } from '@noble/hashes/utils.js';
import { base64urlnopad } from '@scure/base';

export interface ChipRelay {
  open(qr: string): Promise<void>;
  /** Resolves with the sealed bundle; rejects `CHIP_RELAY_GONE` when the session expired or `CHIP_RELAY_TIMEOUT`. */
  receive(qr: string): Promise<Sealed>;
}

export function chipRelay(base: string, f: typeof fetch = fetch, intervalMs = 1000, timeoutMs = 5 * 60_000): ChipRelay {
  const urlOf = (qr: string) => {
    const q = parseQr(qr);
    if (!q) throw new Error('QR_INVALID');
    return `${base}/chip-link/${bytesToHex(q.sessionId)}`;
  };
  return {
    async open(qr) {
      const r = await f(urlOf(qr), { method: 'PUT' });
      if (r.status !== 204) throw new Error(`CHIP_RELAY_OPEN_${r.status}`);
    },
    async receive(qr) {
      const url = urlOf(qr);
      const end = Date.now() + timeoutMs;
      while (Date.now() < end) {
        const r = await f(url);
        if (r.status === 404) throw new Error('CHIP_RELAY_GONE');
        if (r.status === 200) {
          const b = (await r.json()) as { enc: string; ct: string };
          return { enc: base64urlnopad.decode(b.enc), ct: base64urlnopad.decode(b.ct) };
        }
        await new Promise((res) => setTimeout(res, intervalMs));
      }
      throw new Error('CHIP_RELAY_TIMEOUT');
    },
  };
}
