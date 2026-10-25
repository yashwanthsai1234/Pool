// Mutation testing for packages/core (IMPLEMENTATION 5.4). Run: node tools/mutation/run.mjs [file|rest]
// Source: https://stryker-mutator.io/docs/stryker-js/configuration/
import { CRITICAL, REST_EXCLUDE } from './tools/mutation/targets.mjs';

const target = process.env.LEGX_TARGET ?? 'releaseGate'; // a key of CRITICAL, or 'rest'
const critical = Object.keys(CRITICAL);
const rest = target === 'rest';
process.env.LEGX_TESTS = rest ? '' : CRITICAL[target].join(',');
process.env.LEGX_SKIP = rest ? REST_EXCLUDE.join(',') : '';

export default {
  testRunner: 'vitest',
  plugins: ['@stryker-mutator/vitest-runner'],
  vitest: { configFile: 'tools/mutation/vitest.config.ts' },
  mutate: rest
    ? ['packages/core/src/**/*.ts', ...critical.map((f) => `!packages/core/src/${f}.ts`)]
    : [`packages/core/src/${target}.ts`],
  coverageAnalysis: 'perTest',
  concurrency: 2,
  // Stryker's tsconfig rewrite needs a JS TypeScript API, which TypeScript 7 lacks. Pointing at a file that does not exist skips it.
  // The sandbox (not in-place) keeps the shared tree unmutated for other agents.
  tsconfigFile: 'tools/mutation/no-tsconfig.json',
  incremental: true,
  incrementalFile: `tools/mutation/incremental-${target}.json`,
  reporters: ['clear-text', 'json'],
  jsonReporter: { fileName: `tools/mutation/report-${target}.json` },
  thresholds: { high: 90, low: 85, break: rest ? 80 : 85 },
  timeoutMS: 60000,
  tempDirName: '.stryker-tmp',
  ignorePatterns: ['build', '.tools', 'apps', 'services', 'docs', 'tools/mutation/*.json', 'tools/mutation/*.log'],
};
