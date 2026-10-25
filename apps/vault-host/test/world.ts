// Node side of the tests: a signed release, the release host, and vault origins that serve a copy of the real build
// (optionally tampered). Every origin is a separate port on 127.0.0.1, so the browser treats each as its own origin.
// Source: https://nodejs.org/docs/latest-v24.x/api/http.html
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyId } from '@legx/contracts/values';
import { cspHash, sha256Hex } from '@legx/release-hash';
import { writeRelease } from '@legx/release-hash/build';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { bytesToHex } from '@noble/hashes/utils.js';
import { buildBundle } from '../scripts/build.ts';
import { securityHeaders } from '../src/headers.ts';

export type Tamper =
  | 'none'
  | 'js-byte' // one byte appended to the entry script; the page and CSP follow it (an origin owner's attack)
  | 'js-byte-stale-sri' // the same, but the page and CSP still name the old hash: the browser must refuse to run it
  | 'css-byte' // the stylesheet changes; its SRI follows
  | 'wasm-byte' // the wasm file (no SRI) changes
  | 'extra-script' // a second script tag in index.html
  | 'remove-file' // the wasm file is gone
  | 'swap-index'; // index.html is replaced by another page that still loads the real script

export interface VaultOptions {
  appOrigin: string;
  tamper?: Tamper;
  /** What the signed release names as the app origin and lowest version (default: appOrigin, 1.0.0). */
  release?: { appOrigin?: string; minVersion?: string };
  /** Leave out frame-ancestors (to prove the frame also checks the parent's origin itself). */
  noFrameAncestors?: boolean;
}

interface Hosted {
  dir: string;
  server: Server;
  reports: string[];
  headers: Record<string, string>;
  probeHash: string;
}

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.wasm': 'application/wasm',
};

const listen = (server: Server): Promise<number> =>
  new Promise((resolve) =>
    server.unref().listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)),
  );

const readBody = (req: IncomingMessage): Promise<string> =>
  new Promise((resolve) => {
    let s = '';
    req.on('data', (c) => {
      s += c;
    });
    req.on('end', () => resolve(s));
  });

export class World {
  readonly keys = generateNodeSignerKeys(KeyId.parse('release-ed25519'), KeyId.parse('release-ml-dsa-65'));
  readonly signer = nodeSigner(this.keys);
  readonly tmp = mkdtempSync(join(tmpdir(), 'vault-host-'));
  readonly base = join(this.tmp, 'base');
  releaseOrigin = '';
  /** The release each vault origin is told about (the release host answers by the `Origin` header). */
  private releases = new Map<string, string>();
  private hosted = new Map<string, Hosted>();
  private releaseServer!: Server;
  private foreignServer!: Server;
  foreignOrigin = '';
  pub!: { ed25519: string; mlDsa65: string };

  static async create(): Promise<World> {
    const w = new World();
    await w.start();
    return w;
  }

  private async start(): Promise<void> {
    const p = await this.signer.publicKeys();
    this.pub = { ed25519: bytesToHex(p.ed25519), mlDsa65: bytesToHex(p.mlDsa65) };
    this.releaseServer = createServer((req, res) => {
      const origin = req.headers.origin ?? '';
      const body = this.releases.get(origin);
      if (req.url !== '/vault/release.json' || body === undefined) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': origin });
      res.end(body);
    });
    this.releaseOrigin = `http://127.0.0.1:${await listen(this.releaseServer)}`;
    this.foreignServer = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/javascript' });
      res.end('parent.postMessage("foreign-script-ran", "*")');
    });
    this.foreignOrigin = `http://127.0.0.1:${await listen(this.foreignServer)}`;
    await buildBundle({
      outDir: this.base,
      releaseUrl: `${this.releaseOrigin}/vault/release.json`,
      keys: this.pub,
      version: '1.0.0',
    });
  }

  /** Starts a vault origin from a copy of the build. */
  async startVault(o: VaultOptions): Promise<{ origin: string; releaseManifestHash: string }> {
    const dir = mkdtempSync(join(this.tmp, 'vault-'));
    cpSync(this.base, dir, { recursive: true });
    const assets = readdirSync(join(dir, 'assets'));
    const js = join(dir, 'assets', assets.find((f) => f.endsWith('.js')) as string);
    const css = join(dir, 'assets', assets.find((f) => f.endsWith('.css')) as string);
    const wasm = join(dir, 'assets', assets.find((f) => f.endsWith('.wasm')) as string);
    const index = join(dir, 'index.html');
    const append = (f: string) =>
      writeFileSync(f, Buffer.concat([readFileSync(f), Buffer.from(f.endsWith('.wasm') ? [0] : '\n/* x */')]));

    // The release is signed over the pristine build; the tamper happens afterwards, like an attacker on the origin.
    const release = await writeRelease({
      dir,
      version: '1.0.0',
      minVersion: o.release?.minVersion ?? '1.0.0',
      appOrigin: o.release?.appOrigin ?? o.appOrigin,
      signer: this.signer,
    });
    const refreshIntegrity = (file: string) => {
      const html = readFileSync(index, 'utf8');
      const name = file.slice(file.lastIndexOf('/') + 1);
      const fresh = cspHash(sha256Hex(new Uint8Array(readFileSync(file))));
      writeFileSync(
        index,
        html.replace(new RegExp(`(${name.replace('.', '\\.')}"[^>]*integrity=")[^"]*`), `$1${fresh}`),
      );
    };
    switch (o.tamper ?? 'none') {
      case 'js-byte':
        append(js);
        refreshIntegrity(js);
        break;
      case 'js-byte-stale-sri':
        append(js);
        break;
      case 'css-byte':
        append(css);
        refreshIntegrity(css);
        break;
      case 'wasm-byte':
        append(wasm);
        break;
      case 'extra-script':
        writeFileSync(
          index,
          readFileSync(index, 'utf8').replace('</body>', '<script src="./assets/extra.js"></script></body>'),
        );
        writeFileSync(join(dir, 'assets', 'extra.js'), 'parent.postMessage("extra-ran", "*")');
        break;
      case 'remove-file':
        rmSync(wasm);
        break;
      case 'swap-index':
        writeFileSync(index, readFileSync(index, 'utf8').replace('Signing vault', 'Totally the real vault'));
        break;
      case 'none':
        break;
    }
    writeFileSync(join(dir, 'probe.js'), readFileSync(new URL('./probe.js', import.meta.url)));
    writeFileSync(
      join(dir, 'probe.html'),
      '<!doctype html><meta charset="utf-8"><body><script>parent.postMessage("inline-script-ran","*")</script>' +
        `<script src="${this.foreignOrigin}/foreign.js"></script><script src="./probe.js" integrity="${cspHash(sha256Hex(new Uint8Array(readFileSync(join(dir, 'probe.js')))))}"></script>`,
    );

    const server = createServer((req, res) => void this.serve(dir, req, res));
    const port = await listen(server);
    const origin = `http://127.0.0.1:${port}`;
    const entryHash = cspHash(sha256Hex(new Uint8Array(readFileSync(js))));
    const staleHash = cspHash(
      sha256Hex(new Uint8Array(readFileSync(join(this.base, 'assets', js.slice(js.lastIndexOf('/') + 1))))),
    );
    const probeHash = cspHash(sha256Hex(new Uint8Array(readFileSync(join(dir, 'probe.js')))));
    const scriptHashes = o.tamper === 'js-byte-stale-sri' ? [staleHash] : [entryHash];
    const headers = securityHeaders({
      appOrigin: o.appOrigin,
      releaseOrigin: this.releaseOrigin,
      scriptHashes,
      reportUri: '/csp-report',
    });
    if (o.noFrameAncestors) {
      headers['Content-Security-Policy'] = (headers['Content-Security-Policy'] as string).replace(
        /frame-ancestors [^;]*; ?/,
        '',
      );
    }
    this.hosted.set(origin, { dir, server, reports: [], headers, probeHash });
    this.releases.set(origin, JSON.stringify(release));
    return { origin, releaseManifestHash: release.body.manifestHash };
  }

  private async serve(dir: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    const origin = `http://${req.headers.host}`;
    const h = this.hosted.get(origin) as Hosted;
    if (req.method === 'POST' && req.url === '/csp-report') {
      h.reports.push(await readBody(req));
      res.writeHead(204).end();
      return;
    }
    const path = !req.url || req.url === '/' ? '/index.html' : (req.url.split('?')[0]?.split('#')[0] ?? '');
    const file = join(dir, path);
    if (path.includes('..') || !existsSync(file) || !file.startsWith(dir)) {
      res.writeHead(404, h.headers).end();
      return;
    }
    const headers: Record<string, string> = {
      ...h.headers,
      'content-type': TYPES[file.slice(file.lastIndexOf('.'))] ?? 'application/octet-stream',
    };
    if (path === '/probe.html') {
      // Same policy, plus the hash of the probe script (an allowed script that tries the forbidden things).
      const csp = (headers['Content-Security-Policy'] as string).replace(
        /script-src ([^;]*)/,
        `script-src $1 '${h.probeHash}'`,
      );
      headers['Content-Security-Policy'] = csp;
    }
    res.writeHead(200, headers);
    res.end(readFileSync(file));
  }

  reports(origin: string): string[] {
    return this.hosted.get(origin)?.reports ?? [];
  }

  headersOf(origin: string): Record<string, string> {
    return this.hosted.get(origin)?.headers ?? {};
  }

  async close(): Promise<void> {
    for (const h of this.hosted.values()) h.server.close();
    this.releaseServer.close();
    this.foreignServer.close();
    rmSync(this.tmp, { recursive: true, force: true });
  }
}
