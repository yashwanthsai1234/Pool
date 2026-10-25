import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

// P4.1-06: everything a phone downloads for `/party/$role`: the entry, its static imports, its CSS, and the lazy chunk of that route.
// Source: https://vite.dev/config/build-options#build-manifest
export const PHONE_ROUTE_BUDGET_BYTES = 250_000;

type Chunk = { file: string; css?: string[]; imports?: string[]; dynamicImports?: string[]; isEntry?: boolean };

export function phoneRouteFiles(distDir: string): string[] {
  const manifest = JSON.parse(readFileSync(join(distDir, '.vite/manifest.json'), 'utf8')) as Record<string, Chunk>;
  const files = new Set<string>();
  const visit = (key: string) => {
    const chunk = manifest[key];
    if (!chunk || files.has(chunk.file)) return;
    files.add(chunk.file);
    for (const css of chunk.css ?? []) files.add(css);
    for (const dep of chunk.imports ?? []) visit(dep);
  };
  const entryKey = Object.keys(manifest).find((k) => manifest[k]?.isEntry);
  if (!entryKey) throw new Error('no entry chunk in the manifest');
  visit(entryKey);
  for (const key of manifest[entryKey]?.dynamicImports ?? []) if (key.includes('routes/party/')) visit(key);
  return [...files];
}

export function phoneRouteGzipBytes(distDir: string): number {
  return phoneRouteFiles(distDir).reduce((sum, f) => sum + gzipSync(readFileSync(join(distDir, f))).length, 0);
}
