// Break-it (task 5.7): PQ downgrade against the hybrid DSSE envelope (DESIGN 6.13).
import { describe, expect, it } from 'vitest';
import type { KeyId } from '../../../packages/contracts/src/values.ts';
import { ed25519 } from '../../../packages/core/node_modules/@noble/curves/ed25519.js';
import { utf8ToBytes } from '../../../packages/core/node_modules/@noble/hashes/utils.js';
import { type Envelope, pae } from '../../../packages/core/src/evidence.ts';
import { type RegisteredKey, signHybrid, verifyHybrid } from '../../../packages/core/src/hybridEnvelope.ts';
import { mldsaSign, nobleHybridSigner, pqKeygen, toBase64 } from '../../../packages/core/src/pq.ts';

const TYPE = 'application/vnd.legx.attest+json;v=1';
const body = utf8ToBytes(JSON.stringify({ side: 'B', checked_by_role: 'lawyerB', sig_algs: ['ed25519', 'ml-dsa-65'] }));

function holder(name: string) {
  const ed = ed25519.utils.randomSecretKey();
  const pq = pqKeygen();
  return { name, ed, edPub: ed25519.getPublicKey(ed), pq };
}
const lawyerB = holder('lawyerB');
const mallory = holder('bob'); // a deal party with its own registered hybrid key pair

// Each holder's two keys are one enrollment_key row, so they share its id as `pair` (DESIGN 6.3, 9).
const row = (alg: RegisteredKey['alg'], publicKey: Uint8Array, pair: string): RegisteredKey => ({
  alg,
  publicKey,
  validFrom: 0,
  logged: true,
  pair,
});
const registry = new Map<string, RegisteredKey>([
  ['lawyerB#ed25519', row('ed25519', lawyerB.edPub, 'lawyerB')],
  ['lawyerB#ml-dsa-65', row('ml-dsa-65', lawyerB.pq.publicKey, 'lawyerB')],
  ['bob#ed25519', row('ed25519', mallory.edPub, 'bob')],
  ['bob#ml-dsa-65', row('ml-dsa-65', mallory.pq.publicKey, 'bob')],
]);

describe('I-S-P1 the two halves of a hybrid envelope may come from two different holders', () => {
  it('control: an honest envelope verifies', async () => {
    const signer = nobleHybridSigner(
      { keyId: 'lawyerB#ed25519' as KeyId, publicKey: lawyerB.edPub, sign: async (m) => ed25519.sign(m, lawyerB.ed) },
      { keyId: 'lawyerB#ml-dsa-65' as KeyId, secretKey: lawyerB.pq.secretKey },
    );
    expect(verifyHybrid(await signHybrid(TYPE, body, signer), (k) => registry.get(k), 10).ok).toBe(true);
  });

  // Source: DESIGN 6.13 (both signatures by the same holder's enrollment key pair, so a forger needs BOTH a classical
  // and a post-quantum break); https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/ (the two
  // component keys are bound into one identity, otherwise the hybrid gives only the weaker guarantee)
  it("refuses lawyer B's Ed25519 signature next to Bob's ML-DSA-65 signature", () => {
    const m = pae(TYPE, body);
    // Ed25519 half: what a quantum attacker can forge for lawyer B. ML-DSA half: Bob's own key, signed honestly.
    const env: Envelope = {
      payloadType: TYPE,
      payload: toBase64(body),
      signatures: [
        { keyid: 'lawyerB#ed25519', sig: toBase64(ed25519.sign(m, lawyerB.ed)) },
        { keyid: 'bob#ml-dsa-65', sig: toBase64(mldsaSign('ml-dsa-65', mallory.pq.secretKey, m, 'legx/dsse/v1')) },
      ],
    };
    // verifyHybrid returns ok, and its consumers judge the signer from one half: services/coordinator/src/events.ts
    // takes the role from `keyIds.ed25519` alone, services/evidence/src/events.ts `append` and
    // tools/verifier-cli/src/log.ts `checkEvents` check no pairing at all. The post-quantum half then adds nothing.
    expect(verifyHybrid(env, (k) => registry.get(k), 10).ok).toBe(false);
  });
});
