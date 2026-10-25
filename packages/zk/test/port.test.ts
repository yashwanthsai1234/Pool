// P1.17-09: the ZkVerifierPort contract against the replay fake and the offline SDK adapter.
import { describe, expect, it } from 'vitest';
import { offlineZkVerifier, replayZkVerifier } from '../src/port.ts';
import { bodiesOf, loadSet, SET_NAMES } from './fixtures.ts';
import { portRequest, zkVerifierPortContract } from './zkVerifierPort.contract.ts';

const recorded = SET_NAMES.map(loadSet);
zkVerifierPortContract('replay fake', () => replayZkVerifier(recorded.map((s) => s.verification)));

// One recording that holds every set's registry answers and circuit files (all recorded on the same day).
const [first] = recorded as [(typeof recorded)[number]];
const loaders = {
  ...first.loaders,
  rpc: recorded.flatMap((s) => s.loaders.rpc),
  files: Object.assign({}, ...recorded.map((s) => s.loaders.files)),
};
const bodies = new Map(recorded.flatMap((s) => [...bodiesOf(s)]));
zkVerifierPortContract('offline SDK adapter', () => offlineZkVerifier(loaders, bodies));

describe('the offline adapter records SDK errors as messages only (DESIGN 8.7)', () => {
  it('a release request with the strict face match but no face match proof', async () => {
    const v = await offlineZkVerifier(loaders, bodies).verify(portRequest(loadSet('alice-release-facematch')));
    expect(v.verified).toBe(false);
    expect(v.queryResultErrors).toEqual({
      facematch: { commitment: 'The proof does not verify the requested FaceMatch' },
    });
  });
});
