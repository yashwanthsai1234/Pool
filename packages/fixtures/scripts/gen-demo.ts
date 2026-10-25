// Writes packages/fixtures/demo/<name>.json for each demo passport. Run: node packages/fixtures/scripts/gen-demo.ts
import { writeFileSync } from 'node:fs';
import { DEMO_NAMES, demoFile } from '../src/demo.ts';

for (const name of DEMO_NAMES) {
  writeFileSync(new URL(`../demo/${name}.json`, import.meta.url), `${JSON.stringify(demoFile(name), null, 2)}\n`);
}
