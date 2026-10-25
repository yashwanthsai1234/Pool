import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { extname, join, normalize } from 'node:path';
import { gzipSync } from 'node:zlib';
import { build } from 'vite';
import { CSP } from '../csp.ts';

const root = new URL('..', import.meta.url).pathname;

/** Builds the app into a temp dir. `selfDestroy` sets the PWA kill-switch flag the config reads. */
export async function buildTo(selfDestroy: boolean): Promise<string> {
  const outDir = mkdtempSync(join(tmpdir(), 'legx-web-'));
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production'; // vitest sets "test", which would bundle React's development build
  process.env.PWA_SELF_DESTROY = selfDestroy ? '1' : '';
  try {
    await build({ root, mode: 'production', logLevel: 'silent', build: { outDir, emptyOutDir: true } });
  } finally {
    delete process.env.PWA_SELF_DESTROY;
    process.env.NODE_ENV = previous;
  }
  return outDir;
}

const TYPES: Record<string, string> = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json',
  '.json': 'application/json',
};

/** Serves a build directory (swappable, to simulate a redeploy) like `vite preview`: SPA fallback plus the CSP header. */
export async function serve(
  initialDir: string,
): Promise<{ url: string; setDir(dir: string): void; close(): Promise<void> }> {
  let dir = initialDir;
  const server: Server = createServer((req, res) => {
    const path = normalize(new URL(req.url ?? '/', 'http://x').pathname).replace(/^(\.\.[/\\])+/, '');
    let file = join(dir, path);
    try {
      if (!statSync(file).isFile()) throw new Error('not a file');
    } catch {
      file = join(dir, 'index.html');
    }
    res.setHeader('content-type', TYPES[extname(file)] ?? 'application/octet-stream');
    res.setHeader('content-security-policy', CSP);
    res.setHeader('cache-control', 'no-cache');
    // like any static host: gzip, so a throttled run measures what a phone downloads
    if (String(req.headers['accept-encoding']).includes('gzip')) {
      res.setHeader('content-encoding', 'gzip');
      res.end(gzipSync(readFileSync(file)));
    } else res.end(readFileSync(file));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('no address');
  return {
    url: `http://localhost:${address.port}`,
    setDir: (d) => {
      dir = d;
    },
    close: () => new Promise((r) => server.close(() => r())),
  };
}
