// Lists surviving and no-coverage mutants from a Stryker JSON report: node tools/mutation/survivors.mjs <target>
import { readFileSync } from 'node:fs';

const rep = JSON.parse(readFileSync(`tools/mutation/report-${process.argv[2]}.json`, 'utf8'));
for (const [file, f] of Object.entries(rep.files)) {
  const lines = f.source.split('\n');
  const bad = f.mutants.filter((m) => m.status === 'Survived' || m.status === 'NoCoverage');
  console.log(`# ${file}: ${bad.length} not killed of ${f.mutants.length}`);
  for (const m of bad.sort((a, b) => a.location.start.line - b.location.start.line)) {
    const l = m.location.start.line;
    console.log(
      `${m.status === 'Survived' ? 'S' : 'N'} L${l} ${m.mutatorName} -> ${String(m.replacement).slice(0, 60).replace(/\n/g, ' ')} | ${lines[l - 1].trim().slice(0, 90)}`,
    );
  }
}
