// Architecture rules: build/CLEANUP.md rule 5. Docs: https://github.com/sverweij/dependency-cruiser/blob/main/doc/rules-reference.md
/** @type {import('dependency-cruiser').IConfiguration} */
module.exports = {
  forbidden: [
    { name: 'no-circular', severity: 'error', from: {}, to: { circular: true, dependencyTypesNot: ['type-only'] } },
    {
      name: 'core-no-node-only',
      comment: 'OD-27',
      severity: 'error',
      from: { path: '^packages/core/src' },
      to: { dependencyTypes: ['core'] },
    },
    {
      name: 'core-no-upper-layers',
      comment: 'OD-27',
      severity: 'error',
      from: { path: '^packages/core/src' },
      to: { path: '^(services|apps)/' },
    },
    {
      name: 'services-no-noble-pq-sign',
      comment: 'OD-24',
      severity: 'error',
      from: { path: '^services/.+/src' },
      to: { path: '@noble/post-quantum' },
    },
    {
      name: 'apps-no-service-internals',
      severity: 'error',
      from: { path: '^apps/' },
      to: { path: '^services/[^/]+/src/(?!index)' },
    },
  ],
  options: {
    doNotFollow: { path: 'node_modules' },
    exclude: { path: '(^|/)(node_modules|dist|test|test-int)/' },
    // dependency-cruiser has no TypeScript 7 support yet (needs the tsc JS API), so it parses with swc.
    parser: 'swc',
    tsPreCompilationDeps: true,
    combinedDependencies: true,
  },
};
