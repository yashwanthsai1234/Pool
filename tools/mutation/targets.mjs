// Which core tests exercise which critical source file (IMPLEMENTATION 5.4). Most fixtures are built in `beforeAll`, which
// StrykerJS treats as static code: a static mutant reruns every selected test. So each critical file is mutated against
// only the test files that target it (the 2.5k-line paper-deal end-to-end test is left out), plus the mutation-*.test.ts
// files added for the survivors. Source: https://stryker-mutator.io/docs/mutation-testing-elements/static-mutants
export const CRITICAL = {
  releaseGate: ['releaseGate', 'mutation-releaseGate'],
  lockcheck: ['lockcheck', 'appendix', 'mutation-lockcheck'],
  attest: ['attest', 'zkIdentity.attest', 'zkIdentity.result', 'passport/', 'mutation-attest'],
  signedContract: ['signedContract', 'mutation-signedContract'],
  frost: ['frost.', 'mutation-frost'],
  pq: ['pq.test', 'pqHpke', 'pqContexts', 'pqCheckpoint', 'hybridEnvelope', 'mutation-pq'],
  zkIdentity: ['zkIdentity', 'checkpoint.test', 'mutation-zkIdentity'],
};
export const REST_EXCLUDE = ['e2e-paper-deal'];
