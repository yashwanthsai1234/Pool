// The S3 Object Lock ObjectStorePort (production: COMPLIANCE mode; tests and demos may use GOVERNANCE, never bypassed).
// - put: conditional create (`If-None-Match: *`) with a retention date and a SHA-256 checksum that S3 verifies on upload.
//   A 412 means the key exists: compare the stored object's hash to decide `exists` or `conflict`.
// - delete: on a versioned Object Lock bucket a plain DeleteObject only adds a delete marker, so we delete the specific
//   version, which S3 refuses (AccessDenied) before the retention date. We never send `BypassGovernanceRetention`.
// Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
// Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
// Source: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html (ChecksumSHA256, ObjectLockMode, IfNoneMatch)
import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import type { ObjectStorePort } from '@legx/contracts/ports';
import type { Hex32 } from '@legx/contracts/values';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { assertKey } from './key.ts';

const DAY_MS = 86_400_000;

export interface S3ObjectStoreOptions {
  readonly client: Pick<S3Client, 'send'>;
  readonly bucket: string;
  readonly mode: 'COMPLIANCE' | 'GOVERNANCE';
  /** Milliseconds since the epoch, for the retention date. Default: the system clock. */
  readonly now?: () => number;
}

const status = (e: unknown): number | undefined =>
  (e as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
const name = (e: unknown): string | undefined => (e as { name?: string }).name;

/** AWS answers 403 AccessDenied; MinIO answers 400 InvalidRequest "Object is WORM protected". Both mean: still retained. */
const isRetentionRefusal = (e: unknown): boolean =>
  name(e) === 'AccessDenied' ||
  status(e) === 403 ||
  (name(e) === 'InvalidRequest' && /WORM|retention|locked/i.test((e as Error).message));

export function s3ObjectStore(options: S3ObjectStoreOptions): ObjectStorePort {
  const { client, bucket, mode } = options;
  const now = options.now ?? Date.now;

  async function read(key: string): Promise<Uint8Array | undefined> {
    try {
      const res = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
      return res.Body ? await res.Body.transformToByteArray() : undefined;
    } catch (e) {
      if (name(e) === 'NoSuchKey' || status(e) === 404) return undefined;
      throw e;
    }
  }

  return {
    async put(key, bytes, retainDays) {
      assertKey(key);
      const digest = sha256(bytes);
      try {
        await client.send(
          new PutObjectCommand({
            Bucket: bucket,
            Key: key,
            Body: bytes,
            IfNoneMatch: '*',
            ChecksumSHA256: Buffer.from(digest).toString('base64'),
            ObjectLockMode: mode,
            ObjectLockRetainUntilDate: new Date(now() + retainDays * DAY_MS),
          }),
        );
        return { status: 'created', sha256: bytesToHex(digest) as Hex32 };
      } catch (e) {
        if (status(e) !== 412 && status(e) !== 409) throw e; // 409: a concurrent conditional write for the same key
      }
      const existing = await read(key);
      if (!existing) throw new Error(`object ${key}: conditional write refused but no object found`);
      return bytesToHex(sha256(existing)) === bytesToHex(digest)
        ? { status: 'exists', sha256: bytesToHex(digest) as Hex32 }
        : { status: 'conflict' };
    },

    async get(key) {
      assertKey(key);
      return read(key);
    },

    async delete(key) {
      assertKey(key);
      let versionId: string | undefined;
      try {
        versionId = (await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }))).VersionId;
      } catch (e) {
        if (name(e) === 'NotFound' || status(e) === 404) return { status: 'deleted' };
        throw e;
      }
      try {
        await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key, VersionId: versionId }));
        return { status: 'deleted' };
      } catch (e) {
        if (isRetentionRefusal(e)) return { status: 'retained' };
        throw e;
      }
    },
  };
}
