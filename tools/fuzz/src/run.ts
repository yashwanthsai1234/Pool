// CLI: node tools/fuzz/src/run.ts [--seconds N] [--save] [target ...]
// Prints the runs and every distinct crash per target; `--save` writes each new crash input to corpus/<target>/.
import { fuzz, fuzzSeconds, hex, recordKnown, saveCrash } from './harness.ts';
import { targets } from './index.ts';

const args = process.argv.slice(2);
const secondsAt = args.indexOf('--seconds');
const seconds = secondsAt >= 0 ? Number(args[secondsAt + 1]) : fuzzSeconds();
const save = args.includes('--save');
const names = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--seconds');
let failed = false;
for (const t of targets.filter((x) => names.length === 0 || names.includes(x.name))) {
  const r = await fuzz(t, seconds);
  console.log(`${t.name}: ${r.runs} runs, ${r.findings.length} distinct finding(s)`);
  for (const f of r.findings) {
    console.log(`  ${f.known ? `known ${f.known}` : 'NEW'}: ${f.key} (${f.input.length} bytes)`);
    if (save) {
      const file = saveCrash(t.name, f.input);
      if (f.known) recordKnown(t.name, file, f.known);
      console.log(`  saved ${file}`);
    } else if (!f.known) console.log(`  input ${hex(f.input).slice(0, 160)}`);
    if (!f.known) failed = true;
  }
}
process.exit(failed ? 1 : 0);
