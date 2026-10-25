// @legx/recovery-agent: the independent holder of share 3 of each client slot (IMPLEMENTATION 3.9).
// `register(app, deps)` is the shape every service has (Phase 3 "Shape"); `apps/server` composes it.
import type { FastifyInstance } from 'fastify';
import { type AgentHttpDeps, registerAgentRoutes } from './routes.ts';

export { type AgentDeps, AgentRefusal, RecoveryAgent } from './agent.ts';
export { xwingShareCipher } from './cipher.ts';
export { type EvidencePort, MemoryEvidence } from './events.ts';
export { acceptServiceKey, anchorMemo, buildKeyList, readAnchor, signKeyList } from './keylist.ts';
export type { DealInfoPort, NoticePort, RecoveryProofPort } from './ports.ts';
export { RecordedProofs, recoveryBoundValue } from './proofs.ts';
export { RecoveryService, Refusal } from './recovery.ts';
export { ShareVault } from './vault.ts';

/** Mounts the agent's routes on a Fastify instance the caller owns. */
export async function register(app: FastifyInstance, deps: AgentHttpDeps): Promise<void> {
  registerAgentRoutes(app, deps);
}
