import { describe, expect, expectTypeOf, it } from 'vitest';
import { z } from 'zod';
import { FROST_MESSAGE_KINDS, FrostMessage, FrostSignedMessage } from '../src/frost.ts';
import type {
  AppendResult,
  BarLookupResult,
  BarRegistryAdapter,
  ChainHead,
  Checkpoint,
  CheckpointSignature,
  CheckpointSignerPort,
  ClockPort,
  EvidenceStorePort,
  FrostRelayPort,
  HybridPublicKeys,
  HybridSignature,
  LedgerHeader,
  LedgerPort,
  LedgerSnapshot,
  MlDsaContext,
  ObjectStorePort,
  RelayedMessage,
  SignerPort,
  StoredEvent,
  SubmitResult,
  TransparencyLogPort,
  TsaPort,
  ValidatedTx,
  ZkVerifierPort,
} from '../src/ports.ts';
import { ZkVerification, type ZkVerifyRequest } from '../src/records.ts';
import { type Secret, secretPaths } from '../src/secret.ts';
import type { DealId, Hex32, KeyId, XrplAddress, XrplHash } from '../src/values.ts';

describe('P1.2-04 port types', () => {
  it('LedgerPort hides xrpl.js behind validated reads and a reliable submit', () => {
    expectTypeOf<LedgerPort['validatedLedger']>().returns.resolves.toEqualTypeOf<LedgerHeader>();
    expectTypeOf<LedgerPort['ledgerHeader']>().parameters.toEqualTypeOf<[ledgerIndex: number]>();
    expectTypeOf<LedgerPort['snapshot']>().parameter(0).toEqualTypeOf<readonly XrplAddress[]>();
    expectTypeOf<LedgerPort['snapshot']>().returns.resolves.toEqualTypeOf<LedgerSnapshot>();
    expectTypeOf<LedgerPort['tx']>().parameter(0).toEqualTypeOf<XrplHash>();
    expectTypeOf<LedgerPort['tx']>().returns.resolves.toEqualTypeOf<ValidatedTx | undefined>();
    expectTypeOf<LedgerPort['submitReliable']>().returns.resolves.toEqualTypeOf<SubmitResult>();
    expectTypeOf<SubmitResult['status']>().toEqualTypeOf<'validated' | 'rejected' | 'expired'>();
    expectTypeOf<LedgerPort['network']>().toEqualTypeOf<'standalone' | 'testnet' | 'devnet' | 'mainnet'>();
  });

  it('ClockPort returns the validated ledger close_time, nothing else', () => {
    expectTypeOf<keyof ClockPort>().toEqualTypeOf<'now'>();
    expectTypeOf<ClockPort['now']>().returns.resolves.toEqualTypeOf<LedgerHeader>();
    expectTypeOf<LedgerHeader>().toHaveProperty('closeTime');
  });

  it('EvidenceStorePort appends exact bytes and reports a lost seq race', () => {
    expectTypeOf<EvidenceStorePort['head']>().parameters.toEqualTypeOf<[dealId: DealId]>();
    expectTypeOf<EvidenceStorePort['head']>().returns.resolves.toEqualTypeOf<ChainHead>();
    expectTypeOf<EvidenceStorePort['append']>().parameters.toEqualTypeOf<[dealId: DealId, envelope: Uint8Array]>();
    expectTypeOf<EvidenceStorePort['append']>().returns.resolves.toEqualTypeOf<AppendResult>();
    expectTypeOf<Extract<AppendResult, { status: 'seq_taken' }>['head']>().toEqualTypeOf<ChainHead>();
    expectTypeOf<StoredEvent['envelope']>().toEqualTypeOf<Uint8Array>();
    expectTypeOf<EvidenceStorePort['getRecord']>().parameters.toEqualTypeOf<[sha256: Hex32]>();
  });

  it('ObjectStorePort, TransparencyLogPort and TsaPort', () => {
    expectTypeOf<ObjectStorePort['put']>().parameters.toEqualTypeOf<
      [key: string, bytes: Uint8Array, retainDays: number]
    >();
    expectTypeOf<ObjectStorePort['get']>().returns.resolves.toEqualTypeOf<Uint8Array | undefined>();
    expectTypeOf<TransparencyLogPort['checkpoint']>().returns.resolves.toEqualTypeOf<Checkpoint>();
    expectTypeOf<TransparencyLogPort['inclusionProof']>().returns.resolves.toEqualTypeOf<readonly Hex32[]>();
    expectTypeOf<TsaPort['timestamp']>().parameters.toEqualTypeOf<[sha256: Hex32]>();
  });

  it('BarRegistryAdapter takes the bar number as Secret', () => {
    type Query = Parameters<BarRegistryAdapter['lookup']>[0];
    expectTypeOf<Query['barNumber']>().toEqualTypeOf<Secret<string>>();
    // A plain string is not a Secret: a caller must mark it on purpose.
    expectTypeOf<string>().not.toExtend<Secret<string>>();
    expectTypeOf<BarRegistryAdapter['lookup']>().returns.resolves.toEqualTypeOf<BarLookupResult>();
    expectTypeOf<BarLookupResult['status']>().toEqualTypeOf<'active' | 'not_active' | 'not_found'>();
  });

  it('FrostRelayPort moves signed messages only', () => {
    expectTypeOf<FrostRelayPort['send']>().parameter(0).toEqualTypeOf<z.infer<typeof FrostSignedMessage>>();
    expectTypeOf<FrostRelayPort['receive']>().returns.resolves.toEqualTypeOf<readonly RelayedMessage[]>();
  });
});

describe('CheckpointSignerPort (DESIGN 6.13)', () => {
  it('returns an Ed25519 and an ML-DSA-44 signature together, separate from SignerPort', () => {
    expectTypeOf<CheckpointSignerPort['signCheckpoint']>().returns.resolves.toEqualTypeOf<CheckpointSignature>();
    expectTypeOf<keyof CheckpointSignature>().toEqualTypeOf<'ed25519' | 'mlDsa44' | 'keyIds'>();
    expectTypeOf<CheckpointSignerPort['signCheckpoint']>()
      .parameter(0)
      .toEqualTypeOf<{ readonly noteBody: Uint8Array; readonly cosignedSubtree: Uint8Array }>();
    expectTypeOf<{ ed25519: Uint8Array; keyIds: CheckpointSignature['keyIds'] }>().not.toExtend<CheckpointSignature>();
    expectTypeOf<HybridSignature>().not.toExtend<CheckpointSignature>();
  });
});

describe('P1.2-07 SignerPort is hybrid', () => {
  it('signHybrid(msg, ctx) returns { ed25519, mlDsa65, keyIds }', () => {
    expectTypeOf<SignerPort['signHybrid']>().parameters.toEqualTypeOf<[msg: Uint8Array, ctx: MlDsaContext]>();
    expectTypeOf<SignerPort['signHybrid']>().returns.resolves.toEqualTypeOf<HybridSignature>();
    expectTypeOf<keyof HybridSignature>().toEqualTypeOf<'ed25519' | 'mlDsa65' | 'keyIds'>();
    expectTypeOf<HybridSignature['keyIds']>().toEqualTypeOf<{ readonly ed25519: KeyId; readonly mlDsa65: KeyId }>();
    expectTypeOf<MlDsaContext>().toEqualTypeOf<
      | 'legx/dsse/v1'
      | 'legx/pq-binding/v1'
      | 'legx/checkpoint/v1'
      | 'legx/api-request/v1'
      | 'legx/release/v1'
      | 'legx/frost-msg/v1'
      | 'legx/enrollment-pop/v1'
    >();
  });

  it('one signature alone does not satisfy the return type', () => {
    type Ids = HybridSignature['keyIds'];
    expectTypeOf<{ ed25519: Uint8Array; keyIds: Ids }>().not.toExtend<HybridSignature>();
    expectTypeOf<{ mlDsa65: Uint8Array; keyIds: Ids }>().not.toExtend<HybridSignature>();
    const keyIds = {} as Ids;
    const edOnly = async () => ({ ed25519: new Uint8Array(64), keyIds });
    // @ts-expect-error an Ed25519-only signer cannot stand in for signHybrid
    const signHybrid: SignerPort['signHybrid'] = edOnly;
    expect(signHybrid).toBeDefined();
  });

  it('SignerPort has no method that returns one signature', () => {
    expectTypeOf<keyof SignerPort>().toEqualTypeOf<'signHybrid' | 'publicKeys'>();
    expectTypeOf<SignerPort['publicKeys']>().returns.resolves.toEqualTypeOf<HybridPublicKeys>();
  });
});

describe('P1.2-08 ZkVerifierPort and the FROST relay', () => {
  const RESULT_KEYS = [
    'verified',
    'uniqueIdentifier',
    'uniqueIdentifierType',
    'queryResultErrors',
    'proofSha256',
    'vkeyHash',
    'version',
    'committedInputs',
    'scope',
    'domain',
    'trust',
  ] as const;
  const TRUST_KEYS = [
    'chainId',
    'blockNumber',
    'blockHash',
    'registryAddress',
    'root',
    'circuitManifestVersion',
    'vkeyHashes',
    'devMode',
  ] as const;

  it('verify(req) returns the recorded-result shape with the DESIGN 6.10 trust record', () => {
    expectTypeOf<ZkVerifierPort['verify']>().parameters.toEqualTypeOf<[request: ZkVerifyRequest]>();
    expectTypeOf<ZkVerifierPort['verify']>().returns.resolves.toEqualTypeOf<ZkVerification>();
    expectTypeOf<keyof ZkVerification>().toEqualTypeOf<(typeof RESULT_KEYS)[number]>();
    expectTypeOf<keyof ZkVerification['trust']>().toEqualTypeOf<(typeof TRUST_KEYS)[number]>();
    expect(Object.keys(ZkVerification.shape)).toEqual([...RESULT_KEYS]);
    expect(Object.keys(ZkVerification.shape.trust.shape)).toEqual([...TRUST_KEYS]);
  });

  /** Review rule: a relay message may hold a secret share only inside a sealed box. */
  const plainShareFields = (schema: z.ZodType): string[] => {
    const hits: string[] = [];
    const walk = (node: unknown, path: string): void => {
      if (node === null || typeof node !== 'object') return;
      const n = node as Record<string, unknown>;
      const props = (n.properties ?? {}) as Record<string, unknown>;
      if ('enc' in props && 'ciphertext' in props) return; // a SealedBox: opaque to the relay
      for (const [k, v] of Object.entries(props)) {
        if (/secret|share|nonce|private|seed/i.test(k)) hits.push(`${path}/${k}`);
        walk(v, `${path}/${k}`);
      }
      for (const key of ['items', 'anyOf', 'oneOf', 'prefixItems'])
        for (const v of ([] as unknown[]).concat(n[key] ?? [])) walk(v, path);
    };
    walk(z.toJSONSchema(schema), '');
    return hits;
  };

  it('the review rule catches a plain-text share field', () => {
    expect(plainShareFields(z.strictObject({ kind: z.literal('dkg.round2'), signing_share: z.string() }))).toEqual([
      '/signing_share',
    ]);
  });

  it('FrostRelayPort messages carry no secret share in the clear and no Secret field', () => {
    // Reviewed: `share` is a public signature share (sign.share). `kem_secret` and `decrypted_share` are what a
    // complaint reveals from a DKG that aborts and restarts (DESIGN 6.4 rule 3). `old_shares_hash` and
    // `new_shares_hash` hash the PUBLIC verifying shares a deletion statement signs. Any other such field fails review.
    expect(plainShareFields(FrostMessage)).toEqual([
      '/kem_secret',
      '/decrypted_share',
      '/share',
      '/old_shares_hash',
      '/new_shares_hash',
    ]);
    expect(plainShareFields(FrostSignedMessage)).toEqual([]);
    expect(secretPaths(FrostMessage)).toEqual([]);
    expect(FROST_MESSAGE_KINDS).toContain('dkg.round2');
    const round2 = FrostMessage.options.find((o) => o.shape.kind.value === 'dkg.round2');
    expect(Object.keys(round2?.shape ?? {})).toEqual(['session_id', 'deal_id', 'slot', 'from', 'kind', 'to', 'box']);
  });
});
