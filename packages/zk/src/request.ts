// ZKPassport request builders: the domain, the deal scope, the onboarding and the release queries (DESIGN 6.10).
// Source: https://docs.zkpassport.id (request builder) and the @zkpassport/sdk 0.19.2 typings (QueryBuilder:
// gte, gt, in, disclose, facematch(mode = "strict"), bind), checked by test/request.test.ts against the SDK.
import { ZK_DOMAIN } from '@legx/contracts/records';
import { checkBindLength, onboardingBoundValue, releaseBoundValue, zkScope } from '@legx/core/zkIdentity';
import { type QueryBuilder, ZKPassport } from './sdk.ts';

export type ZkRequestCode = 'WRONG_DOMAIN' | 'BOUND_TOO_LONG' | 'FACE_MATCH_REQUIRED';

export class ZkRequestError extends Error {
  readonly code: ZkRequestCode;
  constructor(code: ZkRequestCode) {
    super(code);
    this.code = code;
  }
}

/**
 * The SDK's query builder, from `request()` (with a QR code) or `createQuery()` (offline, the same methods; the
 * SDK types every chained call as the online builder).
 */
export type Builder = QueryBuilder;

/** A builder without a bridge connection, to rebuild the expected query server-side or in tests. */
export const offlineQuery = (domain: string = ZK_DOMAIN): Builder =>
  new ZKPassport(domain).createQuery() as unknown as Builder;

/** What a contract asks about the client, the same at onboarding and at release. */
export interface ContractFacts {
  readonly minAge: number;
  readonly nationalityIn?: readonly string[];
}

/** One day: the SDK's `validity` is the largest age of the expiry-date check, and its dates are whole days. */
const VALIDITY_SECONDS = 86400;
const EXPIRY_MARGIN_SECONDS = 30 * 86400;

/**
 * The settings of every request and verification. The domain is the constant `legx.app`: the identifier depends
 * on it, so a page origin or tunnel host name never reaches the SDK (DESIGN 6.10).
 */
export function requestConfig(o: { dealId: string; devMode: boolean; domain?: string; pageOrigin?: string }) {
  if (o.domain !== undefined && o.domain !== ZK_DOMAIN) throw new ZkRequestError('WRONG_DOMAIN');
  return {
    domain: ZK_DOMAIN,
    scope: zkScope(o.dealId),
    devMode: o.devMode,
    verifierMode: 'local', // never the hosted verifier, which sends proofs to a third party (DESIGN 6.10)
    validity: VALIDITY_SECONDS,
  } as const;
}

/** Binds `custom_data` after the length check; the SDK checks the length only when the phone proves. */
export function bindCustomData(b: Builder, value: string): Builder {
  if (!checkBindLength(value).ok) throw new ZkRequestError('BOUND_TOO_LONG');
  return b.bind('custom_data', value);
}

function withFacts(b: Builder, facts: ContractFacts): Builder {
  const aged = b.gte('age', facts.minAge);
  return facts.nationalityIn ? aged.in('nationality', [...facts.nationalityIn] as never) : aged;
}

/**
 * Onboarding: the contract facts, the name, birth date and nationality disclosed to the client's own lawyer, an
 * expiry after CancelAfter + 30 days, and the bound contract root and planned slot key. Source: DESIGN 6.10
 */
export function onboardingQuery(
  b: Builder,
  s: { facts: ContractFacts; contractRoot: Uint8Array; slotPub: Uint8Array; cancelAfter: number },
): Builder {
  const disclosed = withFacts(b, s.facts)
    .disclose('firstname')
    .disclose('lastname')
    .disclose('birthdate')
    .disclose('nationality');
  const expiring = disclosed.gt('expiry_date', new Date((s.cancelAfter + EXPIRY_MARGIN_SECONDS) * 1000));
  return bindCustomData(expiring, onboardingBoundValue(s.contractRoot, s.slotPub));
}

/**
 * Release: the same facts, the strict face match (on by default, O12) and the bound presenceMsg. The face match
 * goes off only when the deal data allows it. Source: DESIGN 6.10, 6.15
 */
export function releaseQuery(
  b: Builder,
  s: { facts: ContractFacts; presenceMsg: Uint8Array; faceMatch?: boolean; dealAllowsNoFaceMatch?: boolean },
): Builder {
  const faceMatch = s.faceMatch ?? true;
  if (!faceMatch && !s.dealAllowsNoFaceMatch) throw new ZkRequestError('FACE_MATCH_REQUIRED');
  const facts = withFacts(b, s.facts);
  return bindCustomData(faceMatch ? facts.facematch('strict') : facts, releaseBoundValue(s.presenceMsg));
}
