// @legx/firm-cosigner: the firm's HSM service, holder 2 of each lawyer slot (IMPLEMENTATION 3.10).
// `register(app, deps)` is the shape every service has (Phase 3 "Shape"); `apps/server` composes it. The HTTP surface
// is the lawyer-recovery routes of the contract (start with the operations account's signature, cancel, get), served
// by the recovery agent's routes over this service's own `RecoveryService`, and `firmHsm.sign` (routes.ts).
import { type AgentHttpDeps, registerAgentRoutes } from '@legx/recovery-agent/routes';
import type { FastifyInstance } from 'fastify';
import { type FirmHttpDeps, registerFirmRoutes } from './routes.ts';

export { ApprovalError, LawyerApprovals, type WireApproval } from './approval.ts';
export { AuditLog, type AuditSink } from './audit.ts';
export { CosignerRefusal, FirmCosigner, operatorRequestMessage, type SignRequest } from './cosigner.ts';
export { buildFirmKeyList, type FirmListedKey } from './keylist.ts';
export { type FirmHttpDeps, registerFirmRoutes } from './routes.ts';
export { FirmShareVault, wrapKeyFrom } from './vault.ts';

/** Mounts the lawyer-recovery routes and the signing route on a Fastify instance the caller owns. */
export async function register(
  app: FastifyInstance,
  deps: AgentHttpDeps & Partial<Pick<FirmHttpDeps, 'cosigner' | 'onError'>>,
): Promise<void> {
  registerAgentRoutes(app, deps);
  if (deps.cosigner) registerFirmRoutes(app, { ...deps, cosigner: deps.cosigner });
}
