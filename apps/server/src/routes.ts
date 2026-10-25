// The routes of the contract that no service library serves as HTTP: `records.*` (evidence, 3.4), `bar.*` (verifier,
// 3.3), `zk.verify` (3.11), and `health`. Every one runs the signed-request check on the RAW body bytes
// before it reads anything (OD-5); a route whose service call cannot be made from the contract's input says so with 501
// AFTER authentication (see the Known gaps of build/status/3.7.md), so it is mounted and guarded either way.
// Source: https://fastify.dev/docs/latest/Reference/ContentTypeParser/ (parseAs buffer keeps the exact bytes)
import { API_AUTH_HEADER, ApiAuth, type AuthRule } from '@legx/contracts/api';
import { listRoutes } from '@legx/contracts/catalog';
import type { ZkVerifyRequest } from '@legx/contracts/records';
import { authenticate, type Principal } from '@legx/coordinator/auth';
import type { CoordinatorDeps } from '@legx/coordinator/deps';
import { ApiError, badRequest, unauthorized, unprocessable } from '@legx/coordinator/errors';
import { type BundleDeps, buildBundle } from '@legx/evidence/bundle';
import {
  assertOwnSide,
  authenticate as authenticateRecords,
  listClientRecords,
  type RecordsDeps,
  type SignedRequest,
} from '@legx/evidence/records';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { z } from 'zod';
import type { PortSpec } from './config.ts';
import type { ServerDeps } from './deps.ts';
import { verifyZk } from './zk.ts';

const fastifyPath = (p: string) => p.replace(/\{(\w+)\}/g, ':$1');
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

interface RouteDef {
  readonly name: string;
  readonly method: 'GET' | 'POST';
  readonly path: string;
  readonly auth: AuthRule;
  readonly input: z.ZodType;
  readonly output: z.ZodType;
}

const table = new Map<string, RouteDef>(
  listRoutes().map((r) => [
    r.name,
    {
      name: r.name,
      method: r.method as 'GET' | 'POST',
      path: r.path as string,
      auth: r.auth as AuthRule,
      input: r.input as z.ZodType,
      output: r.output as z.ZodType,
    },
  ]),
);

export const routeDef = (name: string): RouteDef => {
  const r = table.get(name);
  if (!r) throw new Error(`contract has no route ${name}`);
  return r;
};

/** `<pair>#ed25519` and `<pair>#ml-dsa-65` (coordinator, DQ-3.2-1) to `<pair>` and `<pair>:pq` (evidence, DQ-3.4-1). */
export function evidenceKeyIds(auth: unknown): unknown {
  const parsed = ApiAuth.safeParse(auth);
  if (!parsed.success) return auth;
  const [ed, pq] = parsed.data.signatures;
  const pair = ed.keyid.replace(/#ed25519$/, '');
  return {
    ...parsed.data,
    signatures: [
      { ...ed, keyid: pair },
      { ...pq, keyid: `${pair}:pq` },
    ],
  };
}

function bodyOf(req: FastifyRequest): { raw: Buffer; json: Record<string, unknown> } {
  const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  if (raw.length === 0) return { raw, json: {} };
  try {
    const parsed: unknown = JSON.parse(raw.toString('utf8'));
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
    return { raw, json: parsed as Record<string, unknown> };
  } catch {
    throw badRequest('the body is not a JSON object');
  }
}

function parseInput<T>(def: RouteDef, req: FastifyRequest, json: Record<string, unknown>): T {
  const r = def.input.safeParse({ ...json, ...(req.params as object) });
  if (!r.success)
    throw badRequest(
      'request does not match the contract',
      r.error.issues.map((i) => ({ path: i.path.map(String).join('.'), message: i.message })),
    );
  return r.data as T;
}

const header = (req: FastifyRequest): string | undefined => req.headers[API_AUTH_HEADER] as string | undefined;

/** An unsigned request is refused before its body is read (the evidence check needs the parsed input to run). */
function requireHeader(req: FastifyRequest): void {
  if (header(req) === undefined) throw unauthorized('auth_malformed', `missing ${API_AUTH_HEADER} header`);
}

/** The coordinator's authentication, called on the raw bytes. */
const principalOf = (
  deps: Pick<CoordinatorDeps, 'db' | 'ledger' | 'lawyerKeys'>,
  def: RouteDef,
  req: FastifyRequest,
  raw: Buffer,
): Promise<Principal> =>
  authenticate(deps as CoordinatorDeps, def.auth, {
    method: req.method,
    path: req.raw.url as string, // pathname + search exactly as sent (OD-8)
    body: raw,
    header: header(req),
    dealId: (req.params as { dealId?: string }).dealId,
  });

function signedRequest(req: FastifyRequest, raw: Buffer): SignedRequest {
  let auth: unknown;
  try {
    auth = header(req) === undefined ? undefined : evidenceKeyIds(JSON.parse(header(req) as string));
  } catch {
    auth = { malformed: true };
  }
  return { method: req.method, path: req.raw.url as string, body: raw, auth };
}

export const notImplemented = (what: string) => new ApiError(501, 'not_implemented', what);

export function mountRoutes(
  app: FastifyInstance,
  d: ServerDeps,
  health: () => Promise<{ profile: string; ports: Record<string, { impl: string; status: 'ok' | 'down' }> }>,
): void {
  const coord = d.coordinator;
  const route = (
    name: string,
    handler: (req: FastifyRequest, raw: Buffer, json: Record<string, unknown>, def: RouteDef) => Promise<unknown>,
  ) => {
    const def = routeDef(name);
    app.route({
      method: def.method,
      url: fastifyPath(def.path),
      handler: async (req, reply) => {
        const { raw, json } = bodyOf(req);
        const out = await handler(req, raw, json, def);
        return reply.send(def.output.parse(out));
      },
    });
  };

  // GET /health: liveness for scripts and tunnels, so it cannot be signed (DQ-3.7-1). It lists ports and the profile only.
  app.get('/health', async (_req, reply) => reply.send(await health()));

  const records = d.evidence?.records;
  const bundle = d.evidence?.bundle;
  route('records.list', async (req, raw, json, def) => {
    requireHeader(req);
    if (!records) throw notImplemented('the evidence service is not composed');
    const input = parseInput<{ dealId: string; side: 'A' | 'B' }>(def, req, json);
    const r = await listClientRecords(records, signedRequest(req, raw), input);
    return { records: r.records.map((x) => ({ ...x, envelope: b64(x.envelope) })) };
  });
  route('records.bundle', async (req, raw, json, def) => {
    requireHeader(req);
    if (!bundle || !records) throw notImplemented('the evidence bundle is not composed');
    const input = parseInput<{ dealId: string; side: 'A' | 'B' }>(def, req, json);
    assertOwnSide(await authenticateRecords(records as RecordsDeps, signedRequest(req, raw), input.dealId), input.side);
    const built = await buildBundle(bundle as BundleDeps, input.dealId);
    return { filename: built.filename, sha256: built.sha256, zip: b64(built.bytes) };
  });

  route('bar.verify', async (req, raw, json, def) => {
    await principalOf(coord, def, req, raw);
    if (!d.verifier) throw notImplemented('the verifier is not composed');
    const input = parseInput<{ opsAccount: string; jurisdiction: string; barNumber: string }>(def, req, json);
    try {
      const row = await d.verifier.service.verify(input);
      await d.verifier.enqueue?.(input.opsAccount);
      return { status: 'active' as const, verificationSha256: row.envelope_sha256, envelope: b64(row.envelope) };
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === 'NOT_FOUND') return { status: 'not_found' as const };
      if (code === 'NOT_ACTIVE') return { status: 'not_active' as const };
      throw e;
    }
  });
  route('bar.record', async (req, raw, _json, def) => {
    await principalOf(coord, def, req, raw);
    const sha = (req.params as { sha256: string }).sha256;
    const row = await coord.db.repos.barVerifications.get(sha);
    if (!row) throw new ApiError(404, 'not_found', 'no such record');
    return { envelope: b64(row.envelope) };
  });
  route('bar.manualEvidence', async (req, raw, json, def) => {
    // The operator keys are pinned like lawyer keys; the coordinator check is told to look them up there.
    await principalOf(
      { ...coord, lawyerKeys: d.operatorKeys ?? (() => undefined) },
      { ...def, auth: { kind: 'signed-request', callers: ['lawyer'] } },
      req,
      raw,
    );
    if (!d.verifier?.manual) throw notImplemented('no manual registry adapter is composed');
    const i = parseInput<{
      jurisdiction: string;
      barNumber: string;
      status: 'active' | 'not_active' | 'not_found';
      url: string;
      evidence: string;
    }>(def, req, json);
    const page = new Uint8Array(Buffer.from(i.evidence, 'base64'));
    d.verifier.manual.upload({
      jurisdiction: i.jurisdiction,
      barNumber: i.barNumber,
      status: i.status,
      page,
      url: i.url,
    });
    return { evidenceSha256: bytesToHex(sha256(page)) };
  });
  route('bar.dealLink', async (req, raw, json, def) => {
    const who = await principalOf(coord, def, req, raw);
    if (!d.verifier?.service.link) throw notImplemented('the verifier is not composed');
    const i = parseInput<{
      dealId: string;
      role: 'LA' | 'LB';
      lawyerPub: string;
      barCommitment: string;
      barNumber: string;
      barSalt: string;
      opsAccount: string;
      verificationSha256: string;
    }>(def, req, json);
    // A lawyer links only their own slot (DESIGN 6.16).
    if (who.kind !== 'deal' || who.role !== (i.role === 'LA' ? 'lawyerA' : 'lawyerB'))
      throw new ApiError(403, 'forbidden', 'a lawyer links only their own slot');
    const deal = await coord.db.repos.deals.get(i.dealId);
    if (!deal) throw new ApiError(404, 'not_found', 'no such deal');
    const envelope = await d.verifier.service.link({
      dealId: i.dealId,
      contractRoot: deal.contract_root,
      role: i.role,
      lawyerPub: i.lawyerPub,
      opsAccount: i.opsAccount,
      barNumber: i.barNumber,
      salt: new Uint8Array(Buffer.from(i.barSalt, 'hex')),
      barCommitment: i.barCommitment,
    });
    return { linkSha256: bytesToHex(sha256(envelope)), envelope: b64(envelope) };
  });
  route('ledger.snapshot', async (req, raw, json, def) => {
    const who = await principalOf(coord, def, req, raw);
    const i = parseInput<{ dealId: string }>(def, req, json);
    if (who.kind !== 'deal' || who.dealId !== i.dealId)
      throw new ApiError(403, 'forbidden', 'a lawyer of this deal only');
    if (!d.releaseInput) throw notImplemented('the release gate is not composed');
    try {
      return { releaseInput: await d.releaseInput(i.dealId) };
    } catch (e) {
      throw unprocessable('snapshot_unavailable', (e as Error).message);
    }
  });
  route('zk.verify', async (req, raw, json, def) => {
    const who = await principalOf(coord, def, req, raw);
    if (!d.zkVerify) throw notImplemented('the ZK verifier is not composed');
    const i = parseInput<{ dealId: string; side: 'A' | 'B'; request: ZkVerifyRequest; zkSalt32: string }>(
      def,
      req,
      json,
    );
    // OD-32: the lawyer of the client's own side verifies; the server checks only the public proofs.
    if (who.kind !== 'deal' || who.role !== (i.side === 'A' ? 'lawyerA' : 'lawyerB'))
      throw new ApiError(403, 'forbidden', "only the client's own lawyer verifies that client's proof");
    return await verifyZk(d.zkVerify, coord.db, i);
  });
}

export type { PortSpec };
