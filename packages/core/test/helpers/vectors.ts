import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const VECTORS = join(dirname(fileURLToPath(import.meta.url)), '../../vectors');

export const readJson = <T>(...parts: string[]): T => JSON.parse(readFileSync(join(VECTORS, ...parts), 'utf8')) as T;

export const listFiles = (...parts: string[]): string[] => readdirSync(join(VECTORS, ...parts)).sort();
