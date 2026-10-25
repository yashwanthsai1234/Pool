// Every named schema of the package: the source of the committed JSON Schema files (documentation) and of
// the golden-example, mutation and fuzz tests. Route schemas are listed as `route.<path>.input|output`.
import type { AnyContractRouter } from '@orpc/contract';
import { isContractProcedure } from '@orpc/contract';
import { z } from 'zod';
import { ApiAuth, contract } from './api.ts';
import { PublicDealData } from './deal.ts';
import { LegxEvent } from './events.ts';
import { FrostMessage, FrostSignedMessage } from './frost.ts';
import {
  AttestationPayload,
  BarDealLink,
  BarVerification,
  DealKey,
  DisclosedFacts,
  EnrollmentKey,
  EnrollmentKeyList,
  Envelope,
  EscrowRecord,
  Finding,
  HybridEnvelope,
  IdentityOnboarded,
  PassportAttestation,
  PqBinding,
  ReleaseGateRecord,
  SealedBox,
  SlotPolicyInput,
  ZkVerification,
  ZkVerifyRequest,
} from './records.ts';
import { WsClientMessage, WsServerMessage } from './ws.ts';

export interface RouteEntry {
  readonly name: string;
  readonly method?: string;
  readonly path?: string;
  readonly auth: unknown;
  readonly input: unknown;
  readonly output: unknown;
}

/** Walks the route table; each leaf is one route. */
export function listRoutes(router: AnyContractRouter = contract, prefix = ''): RouteEntry[] {
  if (isContractProcedure(router)) {
    const def = router['~orpc'];
    return [
      {
        name: prefix,
        method: def.route.method,
        path: def.route.path,
        auth: (def.meta as { auth?: unknown }).auth,
        input: def.inputSchema,
        output: def.outputSchema,
      },
    ];
  }
  return Object.entries(router).flatMap(([k, v]) => listRoutes(v as AnyContractRouter, prefix ? `${prefix}.${k}` : k));
}

const routeSchemas = Object.fromEntries(
  listRoutes().flatMap((r) => [
    [`route.${r.name}.input`, r.input as z.ZodType],
    [`route.${r.name}.output`, r.output as z.ZodType],
  ]),
);

export const SCHEMAS: Readonly<Record<string, z.ZodType>> = {
  ApiAuth,
  PublicDealData,
  Envelope,
  HybridEnvelope,
  PassportAttestation,
  IdentityOnboarded,
  BarVerification,
  BarDealLink,
  AttestationPayload,
  ZkVerification,
  ZkVerifyRequest,
  Finding,
  ReleaseGateRecord,
  EnrollmentKey,
  EnrollmentKeyList,
  SlotPolicyInput,
  DealKey,
  PqBinding,
  EscrowRecord,
  SealedBox,
  DisclosedFacts,
  FrostMessage,
  FrostSignedMessage,
  LegxEvent,
  WsClientMessage,
  WsServerMessage,
  ...routeSchemas,
};

/** JSON Schema (draft 2020-12) of a catalog schema, for documentation and snapshot review. Source: https://zod.dev/json-schema */
export const jsonSchemaOf = (schema: z.ZodType) => z.toJSONSchema(schema);
