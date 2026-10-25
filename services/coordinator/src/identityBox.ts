// The client's salt and ZK disclosure proof, sealed to its own lawyer (OD-36 b; contracts `identityBox.*`). The box is
// X-Wing ciphertext: the coordinator stores it as received, one per (deal, side, kind), never replaces it, and the read
// route lets only that side's lawyer console key fetch it (the route's `ownSideOnly` rule). It cannot open it.
import { sql } from 'kysely';
import { requireDeal } from './deal.ts';
import type { CoordinatorDeps } from './deps.ts';
import { conflict } from './errors.ts';
import { kyselyOf } from './frost/store.ts';

type Kind = 'zk-salt' | 'zk-disclosure';

export async function putIdentityBox(
  deps: CoordinatorDeps,
  dealId: string,
  side: string,
  kind: Kind,
  box: object,
): Promise<{ status: 'stored' }> {
  await requireDeal(deps.db.repos, dealId);
  const r = await sql`INSERT INTO identity_box (deal_id, side, kind, box)
    VALUES (${dealId}, ${side}, ${kind}, ${JSON.stringify(box)}::jsonb) ON CONFLICT DO NOTHING`.execute(
    kyselyOf(deps.db),
  );
  if (Number(r.numAffectedRows ?? 0) === 0)
    throw conflict('box_exists', `the ${kind} box of side ${side} is already stored`);
  return { status: 'stored' };
}

export async function getIdentityBoxes(deps: CoordinatorDeps, dealId: string, side: string) {
  await requireDeal(deps.db.repos, dealId);
  const r = await sql<{ kind: Kind; box: object }>`SELECT kind, box FROM identity_box
    WHERE deal_id = ${dealId} AND side = ${side} ORDER BY kind`.execute(kyselyOf(deps.db));
  return { boxes: r.rows };
}
