// A fake Tessera POSIX sidecar for tests: `POST /add` (index as plain decimal text, as the conformance binary does) and the
// C2SP tlog-tiles read API (`/checkpoint`, `/tile/<L>/<N>[.p/<W>]`). Integration into the published tree is delayed, as in
// Tessera, and partial tiles can be deleted once the full tile exists. It signs with core's `signCheckpoint`, which the
// adapter under test never uses, so note handling is cross-checked as well.
// Source: https://c2sp.org/tlog-tiles and https://github.com/transparency-dev/tessera/blob/main/cmd/conformance/posix/main.go

import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { signCheckpoint } from '@legx/core/pqCheckpoint';
import { ed25519 } from '@noble/curves/ed25519.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { H0, naiveRoot } from './refTree.ts';

export interface FakeTessera {
  readonly url: string;
  readonly origin: string;
  readonly keys: {
    readonly ed: { readonly name: string; readonly publicKey: Uint8Array };
    readonly pq: { readonly name: string; readonly publicKey: Uint8Array };
  };
  readonly requests: string[];
  /** Overrides what the next `/checkpoint` request returns (a lying server). */
  tamper: { checkpointRoot?: Uint8Array; tileByte?: boolean };
  /** Adds `count` leaves straight to the log (no HTTP) and publishes one checkpoint: for large trees. */
  seed(count: number): void;
  close(): Promise<void>;
}

export interface FakeTesseraOptions {
  readonly origin?: string;
  readonly integrateDelayMs?: number;
  readonly deletePartialTiles?: boolean;
  /** Publish only the Ed25519 line, as a stock Tessera does (no 0x06 cosignature). */
  readonly edOnly?: boolean;
}

const tilePathRe = /^\/tile\/(\d+)\/((?:x\d{3}\/)*\d{3})(?:\.p\/(\d+))?$/;

export async function startFakeTessera(options: FakeTesseraOptions = {}): Promise<FakeTessera> {
  const origin = options.origin ?? 'legx.example/log';
  const seed = randomBytes(32);
  const pq = ml_dsa44.keygen();
  const names = { ed: origin, pq: `${origin}-mldsa44` };
  const leaves: Uint8Array[] = []; // leaf hashes
  let published = 0;
  let note = '';
  const tamper: FakeTessera['tamper'] = {};
  const requests: string[] = [];
  const memo = new Map<string, Uint8Array>();

  const mth = (start: number, n: number): Uint8Array => {
    const key = `${start}:${n}`;
    let h = memo.get(key);
    if (!h) {
      h = naiveRoot(leaves.slice(start, start + n));
      if (n === 1 || (n & (n - 1)) === 0) memo.set(key, h);
    }
    return h;
  };

  const publish = () => {
    published = leaves.length;
    note = signCheckpoint(
      { origin, treeSize: published, rootHash: naiveRoot(leaves.slice(0, published)) },
      { name: names.ed, seed },
      { name: names.pq, secretKey: pq.secretKey },
      800_000_000,
    );
    if (options.edOnly) note = note.slice(0, note.trimEnd().lastIndexOf('\n') + 1);
  };
  publish();

  const server: Server = createServer((req, res) => {
    const url = req.url ?? '';
    requests.push(`${req.method} ${url}`);
    const send = (code: number, body: string | Uint8Array = '') => {
      res.statusCode = code;
      res.end(body);
    };
    if (req.method === 'POST' && url === '/add') {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        leaves.push(H0(new Uint8Array(Buffer.concat(chunks))));
        const index = leaves.length - 1;
        setTimeout(publish, options.integrateDelayMs ?? 0);
        send(200, String(index));
      });
      return;
    }
    if (req.method !== 'GET') return send(405);
    if (url === '/checkpoint') {
      if (tamper.checkpointRoot) {
        const root = Buffer.from(tamper.checkpointRoot).toString('base64');
        const [o, n] = note.split('\n');
        return send(200, `${o}\n${n}\n${root}\n\n`);
      }
      return send(200, note);
    }
    const m = tilePathRe.exec(url);
    if (!m) return send(404);
    const level = Number(m[1]);
    const n = Number((m[2] as string).replaceAll('x', '').replaceAll('/', ''));
    const partial = m[3] === undefined ? undefined : Number(m[3]);
    const span = 256 ** level;
    const avail = Math.floor(published / span) - n * 256;
    if (avail <= 0) return send(404);
    if (partial === undefined ? avail < 256 : partial < 1 || partial > 255 || partial > avail) return send(404);
    if (partial !== undefined && avail >= 256 && options.deletePartialTiles) return send(404);
    const width = partial ?? 256;
    const hashes: Uint8Array[] = [];
    for (let j = 0; j < width; j++) hashes.push(mth((n * 256 + j) * span, span));
    const body = concatBytes(...hashes);
    if (tamper.tileByte) body[0] = (body[0] ?? 0) ^ 1;
    return send(200, body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address();
  if (typeof addr !== 'object' || addr === null) throw new Error('no address');
  return {
    url: `http://127.0.0.1:${addr.port}`,
    origin,
    keys: {
      ed: { name: names.ed, publicKey: ed25519.getPublicKey(seed) },
      pq: { name: names.pq, publicKey: pq.publicKey },
    },
    requests,
    tamper,
    seed: (count) => {
      for (let i = 0; i < count; i++) leaves.push(H0(Uint8Array.of(i & 255, (i >> 8) & 255, (i >> 16) & 255)));
      publish();
    },
    close: () => new Promise((r) => server.close(() => r())),
  };
}
