// Break-it 5.7: the offline verifier (tools/verifier-cli) trusts roots that the bundle itself supplies.
// Source: DESIGN 8.8 (the arbitrator checks the bundle offline, trusting only pinned keys and public roots)
// Source: https://www.rfc-editor.org/rfc/rfc3161#section-4 (the time stamp's value comes from a TSA the relying
//         party trusts, independent of the requester)

import { describe, expect, it } from 'vitest';
import { bytesToHex } from '../../../packages/core/node_modules/@noble/hashes/utils.js';
import { zip } from '../../../services/evidence/src/zip.ts';
import { makeBundle, resign, verify } from '../../../tools/verifier-cli/test/helpers.ts';

describe('I-S-E2 fail-open default: an unpinned bundle exits 0', () => {
  it('a bundle from an evidence service the arbitrator never pinned does not PASS', async () => {
    const forged = await makeBundle(); // any self-run evidence service with its own fresh key
    const v = await verify(forged.zip);
    expect(v.report.result).toBe('fail'); // today: PASS with only a warning "pin it with --service-key"
  });
});

describe('I-S-E3 the TSA roots come from the bundle (timestamps/roots.pem)', () => {
  it('a time stamp from a root the bundle supplies (not the arbitrator) is not reported as verified', async () => {
    const b = await makeBundle(); // stamped by a local test authority whose root the service put in roots.pem
    const pin = bytesToHex((await b.deps.signer.publicKeys()).ed25519);
    const v = await verify(b.zip, ['--service-key', pin]);
    const ts = v.report.findings.filter((f) => f.check === 'timestamp' && f.status === 'pass');
    expect(ts).toEqual([]);
  });
});

describe('I-S-E5 events without an inclusion proof are only a warning', () => {
  it('a bundle whose last event has no tlog proof (not in any checkpoint) does not PASS', async () => {
    const b = await makeBundle();
    const proof = b.files
      .map((f) => f.path)
      .filter((p) => p.startsWith('tlog/proofs/'))
      .sort()
      .at(-1) as string;
    const pin = bytesToHex((await b.deps.signer.publicKeys()).ed25519);
    const v = await verify(zip(await resign(b, { [proof]: null })), ['--service-key', pin]);
    expect(v.report.result).toBe('fail'); // today PASS: "no inclusion proof" is a warning
  });
});
