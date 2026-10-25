// Offline bundle check: node verify.ts <unzipped folder>. No network calls. Recomputes every SHA-256 in manifest.json.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = process.argv[2] ?? '.';
const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')) as {
  files: { path: string; sha256: string }[];
};
let bad = 0;
for (const f of manifest.files) {
  const h = createHash('sha256')
    .update(readFileSync(join(dir, f.path)))
    .digest('hex');
  if (h !== f.sha256) {
    bad++;
    process.stderr.write(`MISMATCH ${f.path}\n`);
  }
}
process.stdout.write(
  bad === 0 ? `ok: ${manifest.files.length} files match the manifest\n` : `FAILED: ${bad} files differ\n`,
);
process.exit(bad === 0 ? 0 : 1);
