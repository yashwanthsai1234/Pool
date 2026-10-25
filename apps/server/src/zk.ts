// `zk.verify` (DESIGN 6.10, OD-32): verifies the PUBLIC proofs of one client side and stores the trust record. The
// onboarding facts in clear (the disclosure box, OD-25) are opened by the client's own lawyer in the console, so the
// server never reads `queryResult`: it is replaced by an empty object before the adapter sees it.
// Source: DESIGN.md 6.10; build/DECISIONS.md OD-25, OD-32; services/zk-verifier `verifyAndStore`
import type { ObjectStorePort } from '@legx/contracts/ports';
import type { ZkVerification, ZkVerifyRequest } from '@legx/contracts/records';
import { loadConfig } from '@legx/coordinator/deal';
import { ApiError, unprocessable } from '@legx/coordinator/errors';
import { derivePublicData } from '@legx/coordinator/publicData';
import type { Profile } from '@legx/core/attest';
import { onboardingBoundValue } from '@legx/core/zkIdentity';
import type { Database } from '@legx/db';
import { verifyAndStore, type ZkAdapter, ZkVerifierError } from '@legx/zk-verifier';
import { hexToBytes } from '@noble/hashes/utils.js';

export interface ZkVerifyDeps {
  readonly adapter: ZkAdapter;
  readonly objects: ObjectStorePort;
  readonly profile: Profile;
}

const field = (q: Record<string, unknown>, k: string): Record<string, unknown> => {
  const v = q[k];
  return v !== null && typeof v === 'object' ? (v as Record<string, unknown>) : {};
};

export async function verifyZk(
  z: ZkVerifyDeps,
  db: Database,
  i: { dealId: string; side: 'A' | 'B'; request: ZkVerifyRequest; zkSalt32: string },
): Promise<ZkVerification> {
  const deal = await db.repos.deals.get(i.dealId);
  if (!deal) throw new ApiError(404, 'not_found', 'no such deal');
  const pd = await derivePublicData(db.repos, deal, (await loadConfig(db.repos, i.dealId)).identity_policy);
  if (pd.status !== 'complete')
    throw unprocessable('deal_incomplete', `the deal is not sealed yet: ${pd.missing.join(', ')}`);
  const data = pd.publicData;
  const salt = hexToBytes(i.zkSalt32);
  const bound =
    i.request.stage === 'onboarding'
      ? onboardingBoundValue(hexToBytes(deal.contract_root), hexToBytes(i.side === 'A' ? data.xPubA : data.xPubB))
      : String(field(i.request.originalQuery, 'bind').custom_data ?? ''); // the presence statement is the lawyer's secret
  if (i.request.stage === 'onboarding' && deal.cancel_after === null)
    throw unprocessable('deal_incomplete', 'the escrow CancelAfter is not recorded yet');
  try {
    const out = await verifyAndStore(
      { adapter: z.adapter, db, objects: z.objects },
      {
        dealId: i.dealId,
        side: i.side,
        request: { ...i.request, queryResult: {} as never },
        expect: {
          stage: i.request.stage,
          dealId: i.dealId,
          boundValue: bound,
          profile: z.profile,
          ...(i.request.stage === 'onboarding'
            ? { cancelAfter: deal.cancel_after as number }
            : { identity: { zkSalt32: salt, commitment: i.side === 'A' ? data.commitmentA : data.commitmentB } }),
        },
        salt,
      },
    );
    return out.verification;
  } catch (e) {
    if (e instanceof ZkVerifierError) throw unprocessable(e.code, e.message);
    throw e;
  } finally {
    salt.fill(0);
  }
}
