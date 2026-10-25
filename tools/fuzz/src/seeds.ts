// Seed inputs from the vendored vectors, the fixtures and the contract examples (IMPLEMENTATION 5.2 "Test in all directions").
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const PACKAGES = join(import.meta.dirname, '..', '..', '..', 'packages');

export const pkgPath = (...parts: string[]): string => join(PACKAGES, ...parts);
export const readBytes = (...parts: string[]): Uint8Array => new Uint8Array(readFileSync(pkgPath(...parts)));
export const readJson = <T = unknown>(...parts: string[]): T =>
  JSON.parse(readFileSync(pkgPath(...parts), 'utf8')) as T;
export const listDir = (...parts: string[]): string[] => readdirSync(pkgPath(...parts)).sort();

const enc = (v: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(v));

/** Every `packages/contracts/examples/*.json` (each file is an array of examples), one seed per example, by file name. */
export function contractExamples(): Map<string, Uint8Array[]> {
  return new Map(
    listDir('contracts', 'examples').map((f) => [
      f.replace(/\.json$/, ''),
      readJson<unknown[]>('contracts', 'examples', f).map(enc),
    ]),
  );
}

/** The valid parse inputs for crypto-condition vectors: fulfillment and condition hex. */
export function conditionVectors(): { fulfillment: string; condition: string }[] {
  return listDir('core', 'vectors', 'crypto-conditions').map((f) => {
    const v = readJson<{ fulfillment: string; conditionBinary: string }>('core', 'vectors', 'crypto-conditions', f);
    return { fulfillment: v.fulfillment, condition: v.conditionBinary };
  });
}

export interface DemoPassport {
  readonly name: string;
  readonly dg1: string;
  readonly sod: string;
  readonly dg14: string;
  readonly dg15: string;
}
export const demoPassports = (): DemoPassport[] =>
  listDir('fixtures', 'demo')
    .filter((f) => f.endsWith('.json'))
    .map((f) => readJson<DemoPassport>('fixtures', 'demo', f));

export const jsonBytes = enc;
export const readText = (...parts: string[]): string => readFileSync(pkgPath(...parts), 'utf8');
