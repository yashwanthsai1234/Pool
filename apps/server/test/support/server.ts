// A composed server over the 3.2 test world (PGlite, stub ledger, one deal with all twelve holder keys pinned).
import { createHash } from 'node:crypto';
import type { SignerPort } from '@legx/contracts/ports';
import type { FirmCosigner } from '@legx/firm-cosigner';
import type { AgentHttpDeps } from '@legx/recovery-agent/routes';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { VerifierError } from '@legx/verifier/errors';
import { makeWorld, newDeal, type World } from '../../../../services/coordinator/test/support/world.ts';
import { dealRegistry } from '../../src/evidence.ts';
import { buildServer, type ServerDeps } from '../../src/index.ts';
import { MemorySource } from './feed.ts';

export interface Composed {
  w: World;
  dealId: string;
  source: MemorySource;
  server: Awaited<ReturnType<typeof buildServer>>;
  close(): Promise<void>;
}

export async function compose(over: Partial<ServerDeps> = {}): Promise<Composed> {
  const w = await makeWorld();
  const dealId = await newDeal(w);
  const source = new MemorySource();
  const signer: SignerPort = nodeSigner(generateNodeSignerKeys('evidence-ed' as never, 'evidence-pq' as never));
  const agent = {
    auth: w.deps,
    recoveries: {} as AgentHttpDeps['recoveries'],
    keyList: () => ({ keys: [], signature: '', anchorTx: undefined }) as never,
  };
  const deps: ServerDeps = {
    profile: 'demo',
    ports: { ledger: { impl: 'stub', demo: true }, signer: { impl: 'node', demo: true } },
    coordinator: w.deps,
    verifier: {
      service: {
        verify: async () => {
          throw new VerifierError('NOT_FOUND', 'no such lawyer');
        },
      },
    },
    evidence: {
      records: {
        db: w.db,
        clock: { now: () => w.ledger.validatedLedger() },
        ledger: w.ledger,
        registry: dealRegistry(w.db, signer),
      },
    },
    // the firm HSM route needs a cosigner to be mounted; this one is never asked to sign
    agents: {
      recovery: agent,
      firm: { ...agent, cosigner: { sign: async () => new Uint8Array() } as unknown as FirmCosigner },
    },
    live: { source, pollMs: 50 },
    ...over,
  };
  const server = await buildServer(deps);
  return {
    w,
    dealId,
    source,
    server,
    close: async () => {
      await server.close();
      await w.close();
    },
  };
}

export const sha = (s: string) => createHash('sha256').update(s).digest('hex');
