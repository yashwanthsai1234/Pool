// Service key rotation (P3.12-08). The service signs with one hybrid key pair at a time; a rotation moves it to the
// next pair and is itself evidence: an attestation (hybrid DSSE, record type "attest") naming both generations, signed
// by the OLD pair and by the NEW pair (so the new key proves it is held), recorded before the switch. Old envelopes keep
// verifying, because the registry holds every generation with its validity window: the old one ends at `effectiveAt`.
// The rotation is handed to `record` (WORM copy and log leaf) first; the switch happens only after it succeeded.
// Source: IMPLEMENTATION 3.12 P3.12-08; DESIGN 6.3 (every key's hash enters the evidence log before use)
import type { HybridPublicKeys, SignerPort } from '@legx/contracts/ports';
import { ATTEST_PAYLOAD_TYPE } from '@legx/core/evidence';
import { type KeyRegistry, type RegisteredKey, signHybrid } from '@legx/core/hybridEnvelope';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { canonicalBytes, envelopeBytes } from '../events.ts';

export interface Generation {
  readonly keys: HybridPublicKeys;
  readonly validFrom: number; // Ripple epoch seconds
  readonly validTo?: number;
}

const describe = (k: HybridPublicKeys) => ({
  ed25519_key_id: k.keyIds.ed25519,
  mldsa65_key_id: k.keyIds.mlDsa65,
  ed25519_pub: bytesToHex(k.ed25519),
  mldsa65_pub_sha256: bytesToHex(sha256(k.mlDsa65)),
});

export interface Keyring {
  /** What the services call: signs with the current generation. */
  readonly signer: SignerPort;
  generations(): readonly Generation[];
  /** `base` first, then every generation of this keyring. */
  registry(base?: KeyRegistry): KeyRegistry;
  /** Records the rotation, then switches. Returns the recorded bytes. A failure in `record` leaves the old key in use. */
  rotate(next: SignerPort, effectiveAt: number, record: (bytes: Uint8Array) => Promise<void>): Promise<Uint8Array>;
}

export async function createKeyring(first: SignerPort, validFrom: number): Promise<Keyring> {
  const gens: { signer: SignerPort; gen: Generation }[] = [
    { signer: first, gen: { keys: await first.publicKeys(), validFrom } },
  ];
  const current = () => gens[gens.length - 1] as (typeof gens)[number];
  let rotating: Promise<unknown> = Promise.resolve();

  const entries = (): Map<string, RegisteredKey> => {
    const m = new Map<string, RegisteredKey>();
    for (const { gen } of gens) {
      const w = {
        validFrom: gen.validFrom,
        ...(gen.validTo === undefined ? {} : { validTo: gen.validTo }),
        logged: true,
        pair: `service:${gen.keys.keyIds.ed25519}`,
      };
      m.set(gen.keys.keyIds.ed25519, { alg: 'ed25519', publicKey: gen.keys.ed25519, ...w });
      m.set(gen.keys.keyIds.mlDsa65, { alg: 'ml-dsa-65', publicKey: gen.keys.mlDsa65, ...w });
    }
    return m;
  };

  return {
    signer: {
      publicKeys: () => current().signer.publicKeys(),
      signHybrid: (msg, ctx) => current().signer.signHybrid(msg, ctx),
    },
    generations: () => gens.map((g) => g.gen),
    registry: (base) => {
      const m = entries();
      return (id) => base?.(id) ?? m.get(id);
    },
    rotate(next, effectiveAt, record) {
      const run = rotating.then(async () => {
        const old = current();
        const nextKeys = await next.publicKeys();
        const taken = entries();
        if (taken.has(nextKeys.keyIds.ed25519) || taken.has(nextKeys.keyIds.mlDsa65)) {
          throw new Error('the new key IDs are already in use');
        }
        const body = canonicalBytes({
          type: 'legx/service-key-rotation/v1',
          sig_algs: ['ed25519', 'ml-dsa-65'],
          effective_at: effectiveAt,
          old: describe(old.gen.keys),
          new: describe(nextKeys),
        });
        const bytes = canonicalBytes({
          old: JSON.parse(
            new TextDecoder().decode(envelopeBytes(await signHybrid(ATTEST_PAYLOAD_TYPE, body, old.signer))),
          ),
          new: JSON.parse(new TextDecoder().decode(envelopeBytes(await signHybrid(ATTEST_PAYLOAD_TYPE, body, next)))),
        });
        await record(bytes);
        gens[gens.length - 1] = { signer: old.signer, gen: { ...old.gen, validTo: effectiveAt } };
        gens.push({ signer: next, gen: { keys: nextKeys, validFrom: effectiveAt } });
        return bytes;
      });
      rotating = run.catch(() => undefined);
      return run;
    },
  };
}
