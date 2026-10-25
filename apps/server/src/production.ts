// The production profile's adapters (IMPLEMENTATION 3.7, P5.7-08; closes the "not wired" half of I-3.7-g). Every setting
// comes from the environment, and a missing one stops the start with its name. Nothing here is a demo implementation:
// `assertProfile` has already refused any `LEGX_DEMO_*` variable, a dev-mode or Sepolia ZK setting, or a mock identifier.
//   keys       AWS KMS for the service key (Ed25519 + ML-DSA-65); the log's checkpoint key from a mounted secret file
//   storage    S3 with Object Lock (COMPLIANCE) for evidence; a Tessera sidecar for the transparency log
//   ledger     the configured network (never a faucet), two servers for the bundle's raw anchor JSON
//   registry   the operator path (manual adapter) for each configured jurisdiction: no registry is scraped
// Source: https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html  Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
import { KMSClient } from '@aws-sdk/client-kms';
import { S3Client } from '@aws-sdk/client-s3';
import { KeyId } from '@legx/contracts/values';
import { kmsSigner, secretCheckpointSigner } from '@legx/signer';
import { s3ObjectStore } from '@legx/storage/s3Store';
import { tesseraLog } from '@legx/storage/tesseraLog';
import { manualAdapter } from '@legx/verifier';
import type { LedgerEnv } from '@legx/xrpl/env';
import xrpl from 'xrpl';
import { type Adapters, type Built, buildStack } from './stack.ts';
import { verifyScriptText } from './verifyScript.ts';

type Env = Readonly<Record<string, string | undefined>>;

const need = (env: Env, name: string): string => {
  const v = env[name];
  if (v === undefined || v === '') throw new Error(`production profile: ${name} is not set`);
  return v;
};
const NETWORKS = ['testnet', 'devnet', 'mainnet'] as const;

function ledgerEnv(env: Env, ws: string): LedgerEnv {
  const name = need(env, 'LEGX_NETWORK');
  if (!(NETWORKS as readonly string[]).includes(name))
    throw new Error(`production profile: LEGX_NETWORK must be one of ${NETWORKS.join(', ')}`);
  return { name: name as LedgerEnv['name'], wsUrl: ws };
}

const account = (seed: string) => {
  const w = xrpl.Wallet.fromSeed(seed);
  return { address: w.classicAddress, sign: async (tx: Record<string, unknown>) => w.sign(tx as never).tx_blob };
};

export async function buildProduction(env: Env): Promise<Built> {
  const region = need(env, 'LEGX_AWS_REGION');
  const manual = manualAdapter();
  const jurisdictions = need(env, 'LEGX_BAR_JURISDICTIONS')
    .split(',')
    .map((j) => j.trim())
    .filter(Boolean);
  const rpcUrls = need(env, 'LEGX_ZK_RPC')
    .split(',')
    .map((u) => u.trim())
    .filter(Boolean);
  const origin = need(env, 'LEGX_LOG_ORIGIN');
  const ws2 = env.LEGX_LEDGER_WS_2;
  const adapters: Adapters = {
    profile: 'production',
    ledgerEnv: ledgerEnv(env, need(env, 'LEGX_LEDGER_WS')),
    ...(ws2 ? { ledgerEnv2: ledgerEnv(env, ws2) } : {}),
    signer: kmsSigner({
      client: new KMSClient({ region }),
      kmsKeys: { ed25519: need(env, 'LEGX_KMS_ED25519'), mlDsa65: need(env, 'LEGX_KMS_MLDSA65') },
      keyIds: {
        ed25519: KeyId.parse(need(env, 'LEGX_KMS_KEYID_ED25519')),
        mlDsa65: KeyId.parse(need(env, 'LEGX_KMS_KEYID_MLDSA65')),
      },
    }),
    checkpointSigner: secretCheckpointSigner(need(env, 'LEGX_CHECKPOINT_KEYS_FILE')),
    objects: s3ObjectStore({
      client: new S3Client({
        region,
        ...(env.LEGX_S3_ENDPOINT ? { endpoint: env.LEGX_S3_ENDPOINT, forcePathStyle: true } : {}),
      }),
      bucket: need(env, 'LEGX_S3_BUCKET'),
      mode: 'COMPLIANCE',
    }),
    origin,
    makeLog: () => tesseraLog({ baseUrl: need(env, 'LEGX_TESSERA_URL') }),
    issuer: async () => account(need(env, 'LEGX_ISSUER_SEED')),
    anchor: async () => account(need(env, 'LEGX_ANCHOR_SEED')),
    barAdapters: new Map(jurisdictions.map((j) => [j, manual])),
    manual,
    zk: { profile: 'production', devMode: false, rpcUrls },
    ports: {
      ledger: { impl: need(env, 'LEGX_NETWORK'), demo: false },
      signer: { impl: 'kms', demo: false },
      'checkpoint-signer': { impl: 'secret-file', demo: false },
      'object-store': { impl: 's3-object-lock', demo: false },
      'transparency-log': { impl: 'tessera', demo: false },
      'bar-registry': { impl: 'manual-operator', demo: false },
    },
    verifyScript: await verifyScriptText(),
  };
  return await buildStack(env, adapters);
}
