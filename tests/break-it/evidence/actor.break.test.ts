// Break-it 5.7: services/evidence `append` checks that SOME deal key signed an event, not that the right one did.
// Source: DESIGN 8.2 (each event names its actor; the actor's enrollment key signs it), DESIGN 6.3 (keys are bound
//         to a slot and a holder role)
// Source: https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md (the DSSE keyid identifies the signer)
import { describe, expect, it } from 'vitest';
import { makeWorld } from '../../../services/evidence/test/helpers/world.ts';

describe("I-S-E4 a party signs an event in another actor's name", () => {
  it('Alice (slot A phone key) cannot append `lawyer.approved` claiming to be lawyerB', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    await w.enroll('lawyerB', 'LB');
    const forged = await w.sign(alice, 'lawyerB', 'lawyer.approved', {
      actor: { role: 'lawyerB', keyId: alice.keyId },
    });
    await expect(w.events.append(w.dealId, forged)).rejects.toThrow();
  });

  it('Alice cannot append `release.performed` claiming the coordinator and its key id', async () => {
    const w = await makeWorld();
    const alice = await w.enroll('alice', 'A');
    const forged = await w.sign(alice, 'coordinator', 'release.performed', {
      actor: { role: 'coordinator', keyId: w.service.keyId },
    });
    await expect(w.events.append(w.dealId, forged)).rejects.toThrow();
  });
});
