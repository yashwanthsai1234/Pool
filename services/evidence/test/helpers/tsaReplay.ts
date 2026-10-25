import { readFileSync } from 'node:fs';
import { type Authority, DIGICERT, SSL_COM } from '../../src/tsa.ts';

const read = (name: string, ext: 'req' | 'resp') =>
  new Uint8Array(readFileSync(new URL(`../fixtures/tsa/${name}.${ext}`, import.meta.url)));

export const recorded = (a: Authority) => ({ req: read(a.name, 'req'), resp: read(a.name, 'resp') });

/** A fetch that answers like `authority`, but only to the exact recorded request. Counts and times every call. */
export function replayFetch(
  authorities: readonly Authority[] = [DIGICERT, SSL_COM],
  opts: { delayMs?: Record<string, number>; status?: Record<string, number>; log?: { url: string; at: number }[] } = {},
): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    const a = authorities.find((x) => x.url === url);
    if (!a) throw new Error(`unexpected URL ${url}`);
    opts.log?.push({ url, at: Date.now() });
    const { req, resp } = recorded(a);
    const body = new Uint8Array(init?.body as ArrayBuffer);
    if (body.length !== req.length || !body.every((b, i) => b === req[i]))
      throw new Error('request differs from the recording');
    const delay = opts.delayMs?.[a.name];
    if (delay) await new Promise((r) => setTimeout(r, delay));
    const status = opts.status?.[a.name];
    if (status) return new Response(null, { status, headers: { 'retry-after': '2' } });
    return new Response(resp, { status: 200, headers: { 'content-type': 'application/timestamp-reply' } });
  }) as typeof fetch;
}
