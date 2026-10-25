// Signs an attestation payload with this lawyer's hybrid keys and refuses to hand it on unless the same checks a verifier
// will run accept it (the console's own self-check, DESIGN 4.4).
// Source: DESIGN.md 4.4, 8.4

import { utf8ToBytes } from '@legx/core/dealcore';
import { ATTEST_PAYLOAD_TYPE, type Envelope } from '@legx/core/evidence';
import { signHybrid } from '@legx/core/hybridEnvelope';
import { type ConsoleDeps, ConsoleError } from './ports.ts';

export async function signSelfChecked(
  signer: ConsoleDeps['signer'],
  payload: object,
  verify: (envelope: Envelope) => { ok: true } | { ok: false; code: string },
): Promise<Uint8Array> {
  const env = await signHybrid(ATTEST_PAYLOAD_TYPE, utf8ToBytes(JSON.stringify(payload)), signer);
  const self = verify(env);
  if (!self.ok) throw new ConsoleError('ATTESTATION_SELF_CHECK_FAILED', self.code);
  return utf8ToBytes(JSON.stringify(env));
}
