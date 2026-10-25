// A strict ZIP reader for evidence bundles (DESIGN 8.8). Reads STORED and DEFLATE entries, checks every CRC-32, and
// refuses what a bundle never contains: duplicate or unsafe paths, entries that overlap, encryption, ZIP64, trailing
// bytes after the end record, and sizes beyond the limits below (so a corrupted or hostile archive cannot exhaust memory).
// Source: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT (4.3.7 local header, 4.3.12 central directory,
//   4.3.16 end of central directory, 4.4.4 general purpose flags, 4.4.5 compression method)
// Source: https://nodejs.org/docs/latest-v24.x/api/zlib.html#zlibcrc32data-value
import { crc32, inflateRawSync } from 'node:zlib';

const LOCAL_SIG = 0x04034b50;
const CENTRAL_SIG = 0x02014b50;
const END_SIG = 0x06054b50;
export const MAX_FILE_BYTES = 512 * 1024 * 1024;
export const MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;

export class ZipError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ZipError';
  }
}

/** A path inside the bundle: relative, forward slashes, no `.` or `..` parts, no control characters. */
export function safePath(path: string): boolean {
  return !(
    path === '' ||
    path.startsWith('/') ||
    path.includes('\\') ||
    // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
    /[\u0000-\u001f\u007f]/.test(path) ||
    path.split('/').some((part) => part === '' || part === '.' || part === '..')
  );
}

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Reads a whole archive. Throws `ZipError` on anything unexpected; never anything else. */
export function readZip(bytes: Uint8Array): Map<string, Uint8Array> {
  try {
    return read(bytes);
  } catch (e) {
    throw e instanceof ZipError ? e : new ZipError(`unreadable archive (${(e as Error).message})`);
  }
}

function read(bytes: Uint8Array): Map<string, Uint8Array> {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (at: number) => (at + 2 <= bytes.length ? dv.getUint16(at, true) : fail('truncated'));
  const u32 = (at: number) => (at + 4 <= bytes.length ? dv.getUint32(at, true) : fail('truncated'));
  const fail = (m: string): never => {
    throw new ZipError(m);
  };
  // The end record is the last 22 bytes (a bundle has no archive comment).
  const end = bytes.length - 22;
  if (end < 0 || u32(end) !== END_SIG) return fail('not a ZIP file: no end of central directory');
  if (u16(end + 20) !== 0) return fail('archive comment not allowed');
  if (u16(end + 4) !== 0 || u16(end + 6) !== 0) return fail('multi-disk archive');
  const count = u16(end + 10);
  if (u16(end + 8) !== count) return fail('entry counts disagree');
  const centralSize = u32(end + 12);
  const centralAt = u32(end + 16);
  if (count === 0xffff || centralSize === 0xffffffff || centralAt === 0xffffffff) return fail('ZIP64 not supported');
  if (centralAt + centralSize !== end) return fail('central directory does not end where the end record starts');

  const files = new Map<string, Uint8Array>();
  const spans: [number, number][] = [];
  let total = 0;
  let at = centralAt;
  for (let i = 0; i < count; i++) {
    if (u32(at) !== CENTRAL_SIG) return fail('bad central directory entry');
    const flags = u16(at + 8);
    const method = u16(at + 10);
    const crc = u32(at + 16);
    const csize = u32(at + 20);
    const size = u32(at + 24);
    const nameLength = u16(at + 28);
    const extra = u16(at + 30);
    const comment = u16(at + 32);
    const local = u32(at + 42);
    if (flags & 0x1 || flags & 0x40) return fail('encrypted entries not supported');
    if (flags & 0x8) return fail('data descriptors not supported');
    total += size;
    if (size > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES) return fail('archive too large');
    if (at + 46 + nameLength > end) return fail('truncated');
    const path = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(at + 46, at + 46 + nameLength));
    if (!safePath(path)) return fail(`unsafe path ${JSON.stringify(path)}`);
    if (files.has(path)) return fail(`duplicate path ${path}`);
    if (u32(local) !== LOCAL_SIG) return fail(`bad local header for ${path}`);
    if (
      u16(local + 26) !== nameLength ||
      !same(bytes.subarray(local + 30, local + 30 + nameLength), bytes.subarray(at + 46, at + 46 + nameLength))
    ) {
      return fail(`local header name differs for ${path}`);
    }
    const start = local + 30 + nameLength + u16(local + 28);
    if (start + csize > centralAt) return fail(`data of ${path} runs into the central directory`);
    spans.push([local, start + csize]);
    const raw = bytes.subarray(start, start + csize);
    let data: Uint8Array;
    if (method === 0) {
      if (csize !== size) return fail(`size mismatch in ${path}`);
      data = raw.slice();
    } else if (method === 8) {
      data = new Uint8Array(inflateRawSync(raw, { maxOutputLength: Math.max(size, 1) }));
      if (data.length !== size) return fail(`size mismatch in ${path}`);
    } else return fail(`unsupported compression method ${method} in ${path}`);
    if (crc32(data) !== crc) return fail(`CRC-32 mismatch in ${path}`);
    files.set(path, data);
    at += 46 + nameLength + extra + comment;
  }
  if (at !== end) return fail('central directory has extra bytes');
  spans.sort((a, b) => a[0] - b[0]);
  for (let i = 1; i < spans.length; i++) {
    if ((spans[i] as [number, number])[0] < (spans[i - 1] as [number, number])[1]) return fail('entries overlap');
  }
  return files;
}
