// Appends a hybrid-signed evidence event by this lawyer (DESIGN 8.1). The evidence port assigns seq and prev_hash.
// Source: DESIGN 8.1 (event envelope), IMPLEMENTATION 1.12 (event shape)
import { LegxEvent } from '@legx/contracts/events';
import { utf8ToBytes } from '@legx/core/dealcore';
import { PAYLOAD_TYPE } from '@legx/core/evidence';
import { signHybrid } from '@legx/core/hybridEnvelope';
import type { ConsoleDeps } from './ports.ts';

export const createEventAppender =
  (deps: ConsoleDeps) =>
  async (kind: string, data: Record<string, unknown>): Promise<Uint8Array> => {
    const { deal, role } = deps;
    const { keyIds } = await deps.signer.publicKeys();
    const statement = {
      _type: 'https://in-toto.io/Statement/v1',
      subject: [{ name: `deal:${deal.id}`, digest: { sha256: deal.data.contractRoot } }],
      predicateType: 'https://legx.dev/event/v1',
      predicate: {
        ...(await deps.evidence.fields(utf8ToBytes(JSON.stringify(data)))),
        deal_id: deal.id,
        kind,
        actor: { role: role === 'LA' ? 'lawyerA' : 'lawyerB', key_id: keyIds.ed25519 },
        sig_algs: ['ed25519', 'ml-dsa-65'],
        data,
      },
    };
    LegxEvent.parse(statement);
    const env = await signHybrid(PAYLOAD_TYPE, utf8ToBytes(JSON.stringify(statement)), deps.signer);
    const bytes = utf8ToBytes(JSON.stringify(env));
    await deps.evidence.append(bytes);
    return bytes;
  };
