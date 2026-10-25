// A deterministic ZIP writer and a strict reader (DESIGN 8.8: "a deterministic ZIP: two builds give the same bytes").
// Determinism comes from fixing everything a general ZIP tool leaves to the machine: entries sorted by path (bytewise),
// STORED (no compression, so no zlib version in the bytes), the DOS time 1980-01-01 00:00:00, one fixed "version made
// by", fixed attributes, no extra fields, no comments, no data descriptors, no ZIP64 (a bundle is far below 4 GiB and
// 65,535 entries). Any standard unzip tool reads the result.
// Source: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT (4.3.7 local header, 4.3.12 central directory,
//   4.3.16 end of central directory, 4.4.4 flag bit 11 = UTF-8 names, 4.4.6 DOS date and time)
// Source: https://nodejs.org/docs/latest-v24.x/api/zlib.html#zlibcrc32data-value (CRC-32, Node 22.2 and later)
import { crc32 } from 'node:zlib';

const LOCAL_SIG = 0x04034b50;
const CENTRAL_SIG = 0x02014b50;
const END_SIG = 0x06054b50;
const UTF8_FLAG = 0x0800;
const DOS_TIME = 0; // 00:00:00
const DOS_DATE = (0 << 9) | (1 << 5) | 1; // 1980-01-01
const VERSION_MADE_BY = (3 << 8) | 20; // Unix, ZIP 2.0
const ATTRS = (0o100644 << 16) >>> 0; // regular file, rw-r--r--
const MAX_ENTRIES = 0xffff;
const MAX_BYTES = 0xffffffff;

const utf8 = new TextEncoder();

export interface ZipFile {
  readonly path: string;
  readonly bytes: Uint8Array;
}

/** A path inside the bundle: relative, forward slashes, no `.` or `..` parts, no control characters. */
export function assertZipPath(path: string): void {
  const bad =
    path === '' ||
    path.startsWith('/') ||
    path.includes('\\') ||
    // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
    /[\u0000-\u001f\u007f]/.test(path) ||
    path.split('/').some((part) => part === '' || part === '.' || part === '..');
  if (bad) throw new Error(`bad path in the bundle: ${JSON.stringify(path)}`);
}

const compare = (a: Uint8Array, b: Uint8Array) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return (a[i] as number) - (b[i] as number);
  return a.length - b.length;
};

export function zip(files: readonly ZipFile[]): Uint8Array {
  if (files.length > MAX_ENTRIES) throw new Error('too many files for a ZIP without ZIP64');
  const entries = files
    .map((f) => {
      assertZipPath(f.path);
      return { name: utf8.encode(f.path), path: f.path, bytes: f.bytes };
    })
    .sort((a, b) => compare(a.name, b.name));
  for (let i = 1; i < entries.length; i++) {
    if ((entries[i] as { path: string }).path === (entries[i - 1] as { path: string }).path) {
      throw new Error(`duplicate path in the bundle: ${(entries[i] as { path: string }).path}`);
    }
  }
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  for (const e of entries) {
    const crc = crc32(e.bytes);
    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, LOCAL_SIG, true);
    local.setUint16(4, 20, true); // version needed
    local.setUint16(6, UTF8_FLAG, true);
    local.setUint16(8, 0, true); // STORED
    local.setUint16(10, DOS_TIME, true);
    local.setUint16(12, DOS_DATE, true);
    local.setUint32(14, crc, true);
    local.setUint32(18, e.bytes.length, true);
    local.setUint32(22, e.bytes.length, true);
    local.setUint16(26, e.name.length, true);
    local.setUint16(28, 0, true);
    const c = new DataView(new ArrayBuffer(46));
    c.setUint32(0, CENTRAL_SIG, true);
    c.setUint16(4, VERSION_MADE_BY, true);
    c.setUint16(6, 20, true);
    c.setUint16(8, UTF8_FLAG, true);
    c.setUint16(10, 0, true);
    c.setUint16(12, DOS_TIME, true);
    c.setUint16(14, DOS_DATE, true);
    c.setUint32(16, crc, true);
    c.setUint32(20, e.bytes.length, true);
    c.setUint32(24, e.bytes.length, true);
    c.setUint16(28, e.name.length, true);
    c.setUint32(38, ATTRS, true);
    c.setUint32(42, offset, true);
    parts.push(new Uint8Array(local.buffer), e.name, e.bytes);
    central.push(new Uint8Array(c.buffer), e.name);
    offset += 30 + e.name.length + e.bytes.length;
    if (offset > MAX_BYTES) throw new Error('the bundle is too large for a ZIP without ZIP64');
  }
  const centralSize = central.reduce((n, p) => n + p.length, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, END_SIG, true);
  end.setUint16(8, entries.length, true);
  end.setUint16(10, entries.length, true);
  end.setUint32(12, centralSize, true);
  end.setUint32(16, offset, true);
  const out = new Uint8Array(offset + centralSize + 22);
  let at = 0;
  for (const p of [...parts, ...central, new Uint8Array(end.buffer)]) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Reads a ZIP made by `zip` (STORED entries only) and checks every CRC-32. Throws on anything else. */
export function unzip(bytes: Uint8Array): ZipFile[] {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 22 || dv.getUint32(bytes.length - 22, true) !== END_SIG)
    throw new Error('not a ZIP made by this service');
  const count = dv.getUint16(bytes.length - 12, true);
  let at = dv.getUint32(bytes.length - 6, true);
  const files: ZipFile[] = [];
  for (let i = 0; i < count; i++) {
    if (dv.getUint32(at, true) !== CENTRAL_SIG) throw new Error('bad central directory');
    const method = dv.getUint16(at + 10, true);
    const crc = dv.getUint32(at + 16, true);
    const size = dv.getUint32(at + 24, true);
    const nameLength = dv.getUint16(at + 28, true);
    const local = dv.getUint32(at + 42, true);
    if (method !== 0) throw new Error('only STORED entries are supported');
    const path = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(at + 46, at + 46 + nameLength));
    assertZipPath(path);
    if (dv.getUint32(local, true) !== LOCAL_SIG) throw new Error('bad local header');
    const start = local + 30 + dv.getUint16(local + 26, true) + dv.getUint16(local + 28, true);
    const data = bytes.slice(start, start + size);
    if (data.length !== size || crc32(data) !== crc) throw new Error(`CRC-32 mismatch in ${path}`);
    files.push({ path, bytes: data });
    at += 46 + nameLength + dv.getUint16(at + 30, true) + dv.getUint16(at + 32, true);
  }
  return files;
}
