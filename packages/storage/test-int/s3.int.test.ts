// P3.6-03 on S3: the same ObjectStorePort contract suite against MinIO with Object Lock, in a container.
// Image: pgsty/minio (a community build of MinIO; the official minio/minio and quay.io images are no longer pullable).
// Source: https://min.io/docs/minio/linux/administration/object-management/object-retention.html

import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import {
  CreateBucketCommand,
  ListBucketsCommand,
  ListObjectVersionsCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { s3ObjectStore } from '../src/s3Store.ts';
import { objectStoreContract } from '../test/helpers/objectStoreContract.ts';

const NAME = 'legx-3.6-minio';
const PORT = 9101;
const IMAGE = 'pgsty/minio@sha256:b6bfe7239bfc83fb90d31612d9704d86039dd714f7904b3f1ad68f211e602372';
const docker = (...args: string[]) => execFileSync('docker', args, { stdio: 'pipe' }).toString();

const client = new S3Client({
  endpoint: `http://127.0.0.1:${PORT}`,
  region: 'us-east-1',
  forcePathStyle: true,
  credentials: { accessKeyId: 'legxminio', secretAccessKey: 'legxminio-secret' },
});

const lockedBucket = async () => {
  const bucket = `legx-${randomUUID().slice(0, 8)}`;
  await client.send(new CreateBucketCommand({ Bucket: bucket, ObjectLockEnabledForBucket: true }));
  return bucket;
};

beforeAll(async () => {
  try {
    docker('rm', '-f', NAME);
  } catch {
    // no earlier container
  }
  docker(
    'run',
    '-d',
    '--name',
    NAME,
    '-p',
    `${PORT}:9000`,
    '-e',
    'MINIO_ROOT_USER=legxminio',
    '-e',
    'MINIO_ROOT_PASSWORD=legxminio-secret',
    IMAGE,
    'server',
    '/data',
  );
  for (let i = 0; i < 60; i++) {
    try {
      await client.send(new ListBucketsCommand({}));
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  throw new Error('MinIO did not start');
}, 120_000);

afterAll(() => {
  docker('rm', '-f', NAME);
});

objectStoreContract('S3 Object Lock, COMPLIANCE (MinIO)', async () =>
  s3ObjectStore({ client, bucket: await lockedBucket(), mode: 'COMPLIANCE' }),
);
objectStoreContract('S3 Object Lock, GOVERNANCE (MinIO)', async () =>
  s3ObjectStore({ client, bucket: await lockedBucket(), mode: 'GOVERNANCE' }),
);

describe('S3 specifics', () => {
  it('a refused delete leaves no delete marker and the version is still there', async () => {
    const bucket = await lockedBucket();
    const s = s3ObjectStore({ client, bucket, mode: 'COMPLIANCE' });
    await s.put('a/k', new Uint8Array([1]), 1);
    expect(await s.delete('a/k')).toEqual({ status: 'retained' });
    const v = await client.send(new ListObjectVersionsCommand({ Bucket: bucket }));
    expect(v.DeleteMarkers ?? []).toHaveLength(0);
    expect(v.Versions).toHaveLength(1);
  });

  it('the object really carries the lock: retention mode and date are set by the store', async () => {
    const bucket = await lockedBucket();
    const s = s3ObjectStore({ client, bucket, mode: 'COMPLIANCE', now: () => Date.now() });
    await s.put('k', new Uint8Array([1]), 30);
    const { HeadObjectCommand } = await import('@aws-sdk/client-s3');
    const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: 'k' }));
    expect(head.ObjectLockMode).toBe('COMPLIANCE');
    const days = ((head.ObjectLockRetainUntilDate?.getTime() ?? 0) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(29.9);
    expect(days).toBeLessThan(30.1);
  });

  it('refuses to store into a bucket without Object Lock instead of silently storing unlocked bytes', async () => {
    const bucket = `legx-nolock-${randomUUID().slice(0, 8)}`;
    await client.send(new CreateBucketCommand({ Bucket: bucket }));
    await expect(
      s3ObjectStore({ client, bucket, mode: 'COMPLIANCE' }).put('k', new Uint8Array([1]), 1),
    ).rejects.toThrow();
  });

  it('S3 verifies the checksum we send: a body that differs from it is rejected', async () => {
    const bucket = await lockedBucket();
    await expect(
      client.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: 'k',
          Body: new Uint8Array([1, 2, 3]),
          ChecksumSHA256: Buffer.from(new Uint8Array(32)).toString('base64'),
        }),
      ),
    ).rejects.toThrow();
  });
});
