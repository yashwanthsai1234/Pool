#!/usr/bin/env node
import { run } from './cli.ts';

process.exitCode = await run(process.argv.slice(2), {
  out: (t) => process.stdout.write(t),
  err: (t) => process.stderr.write(t),
});
