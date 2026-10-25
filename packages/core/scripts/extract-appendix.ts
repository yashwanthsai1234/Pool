// Extracts DESIGN.md Appendix A (the starting code) into a directory, byte for byte.
// Usage: node packages/core/scripts/extract-appendix.ts [--out <dir>] [--design <DESIGN.md>] [--force]
// Without --force it refuses to overwrite a file, because task 1.3 adapted the extracted files by hand.
// To check for drift when Appendix A changes: extract into a scratch directory and diff it against packages/core.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export type Block = { path: string; content: string; sha256: string };

const START = '## Appendix A';
const END = '## Appendix B';

// Source: https://spec.commonmark.org/0.31.2/#fenced-code-blocks (a fence is three backticks at the start of a line).
export function extractAppendixA(markdown: string): Block[] {
  const lines = markdown.split('\n');
  const from = lines.findIndex((l) => l.startsWith(START));
  const to = lines.findIndex((l, i) => i > from && l.startsWith(END));
  if (from < 0 || to < 0) throw new Error('Appendix A or Appendix B heading not found');
  const blocks: Block[] = [];
  let path: string | undefined;
  let body: string[] | undefined;
  for (const line of lines.slice(from + 1, to)) {
    if (body === undefined) {
      const h = /^### (\S+)/.exec(line);
      if (h) path = h[1];
      else if (line.startsWith('```') && path !== undefined) body = [];
    } else if (line.startsWith('```')) {
      const content = `${body.join('\n')}\n`;
      blocks.push({ path: path as string, content, sha256: createHash('sha256').update(content).digest('hex') });
      path = undefined;
      body = undefined;
    } else {
      body.push(line);
    }
  }
  if (body !== undefined) throw new Error(`unterminated fence under ${path}`);
  return blocks;
}

export function writeBlocks(blocks: Block[], outDir: string, force: boolean): void {
  for (const b of blocks) {
    const file = join(outDir, b.path);
    if (existsSync(file) && !force) throw new Error(`${file} exists (use --force)`);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, b.content);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (name: string, dflt: string) => {
    const i = args.indexOf(name);
    return i >= 0 ? (args[i + 1] ?? dflt) : dflt;
  };
  const here = dirname(fileURLToPath(import.meta.url));
  const blocks = extractAppendixA(readFileSync(opt('--design', join(here, '../../../DESIGN.md')), 'utf8'));
  writeBlocks(blocks, opt('--out', join(here, '..')), args.includes('--force'));
  for (const b of blocks) process.stdout.write(`${b.sha256}  ${b.path}\n`);
}
