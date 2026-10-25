// Builds the ZKPassport request of the party app (onboarding at P5, release at P7) and shows nothing until the bound
// value passed our length check. The domain is the constant `legx.app`, the scope `legx/v1/<dealId>`.
// Source: DESIGN 6.10, IMPLEMENTATION 4.8; @zkpassport/sdk 0.19.2 QueryBuilder (gte, in, disclose, gt, facematch, bind)
import { ZK_DOMAIN } from '@legx/contracts/records';
import { type Profile, presenceMsg, type Side } from '@legx/core/attest';
import { checkBindLength, onboardingBoundValue, releaseBoundValue, zkScope } from '@legx/core/zkIdentity';
import { assertDevModeAllowed, checkAnchorAge, ZkWebError } from './policy.ts';
import type { ZkBuilder, ZkCallbacks, ZkSdk } from './sdk.ts';

const DAY = 86_400;
const VALIDITY_SECONDS = DAY;
const EXPIRY_MARGIN_SECONDS = 30 * DAY;

interface ContractFacts {
  readonly minAge: number;
  readonly nationalityIn?: readonly string[];
}

interface Common {
  readonly sdk: ZkSdk;
  readonly profile: Profile;
  readonly devMode: boolean;
  readonly dealId: string;
  readonly facts: ContractFacts;
}

export interface OnboardingInput extends Common {
  readonly stage: 'onboarding';
  readonly contractRoot: Uint8Array;
  readonly slotPub: Uint8Array;
  readonly cancelAfter: number;
}

export interface ReleaseInput extends Common {
  readonly stage: 'release';
  readonly side: Side;
  readonly dealSeal: Uint8Array;
  /** The ledger hash the phone read itself, with its close time and the current ledger time (unix seconds). */
  readonly ledgerHash: Uint8Array;
  readonly ledgerCloseTime: number;
  readonly nowLedgerTime: number;
  readonly maxAgeSeconds?: number;
  readonly lawyerNonce: Uint8Array;
  /** Strict face match is on unless the deal data allows otherwise (O12). */
  readonly faceMatch?: boolean;
  readonly dealAllowsNoFaceMatch?: boolean;
}

export interface ZkRequest extends ZkCallbacks {
  readonly url: string;
  readonly boundValue: string;
}

function withFacts(b: ZkBuilder, facts: ContractFacts): ZkBuilder {
  const aged = b.gte('age', facts.minAge);
  return facts.nationalityIn ? aged.in('nationality', [...facts.nationalityIn]) : aged;
}

/** What the party app binds: the onboarding hash, or presenceMsg after the freshness and nonce-length checks. */
export function boundValueOf(i: OnboardingInput | ReleaseInput): string {
  if (i.stage === 'onboarding') return onboardingBoundValue(i.contractRoot, i.slotPub);
  const stale = checkAnchorAge(i.ledgerCloseTime, i.nowLedgerTime, i.maxAgeSeconds);
  if (stale) throw new ZkWebError(stale);
  return releaseBoundValue(presenceMsg(i.dealSeal, i.side, i.ledgerHash, i.lawyerNonce));
}

/**
 * Asks the SDK for a request, or throws before the SDK is asked: devMode outside the demo profile, a stale ledger
 * anchor, a bound value over 506 bytes, a release without face match that the deal does not allow.
 * Source: DESIGN 6.10 ("Bound data ... our code checks the length before it shows the QR code")
 */
export async function buildZkRequest(i: OnboardingInput | ReleaseInput): Promise<ZkRequest> {
  assertDevModeAllowed(i.profile, i.devMode);
  const faceMatch = i.stage === 'release' ? (i.faceMatch ?? true) : false;
  if (i.stage === 'release' && !faceMatch && !i.dealAllowsNoFaceMatch) throw new ZkWebError('FACE_MATCH_REQUIRED');
  const boundValue = boundValueOf(i);
  if (!checkBindLength(boundValue).ok) throw new ZkWebError('BOUND_TOO_LONG');
  const base = await i.sdk.request({
    domain: ZK_DOMAIN,
    scope: zkScope(i.dealId),
    devMode: i.devMode,
    validity: VALIDITY_SECONDS,
    verifierMode: 'local', // never the hosted verifier (DESIGN 6.10)
  });
  const facts = withFacts(base, i.facts);
  let query: ZkBuilder;
  if (i.stage === 'onboarding') {
    query = facts
      .disclose('firstname')
      .disclose('lastname')
      .disclose('birthdate')
      .disclose('nationality')
      .gt('expiry_date', new Date((i.cancelAfter + EXPIRY_MARGIN_SECONDS) * 1000));
  } else {
    query = faceMatch ? facts.facematch('strict') : facts;
  }
  const done = query.bind('custom_data', boundValue).done();
  return Object.assign(done, { boundValue });
}
