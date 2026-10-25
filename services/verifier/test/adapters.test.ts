// P3.3-01 (contract suite on manual and demo), P3.3-02, P3.3-03, P3.3-09, and a broken registry (time-outs, garbage).
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { BarLookup } from '@legx/contracts/ports';
import { startRegistry } from '@legx/mock-bar-registry';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { demoAdapter, manualAdapter } from '../src/adapters.ts';
import { adapterContract } from './support/adapterContract.ts';

const q = (barNumber: string, jurisdiction = 'XA'): BarLookup => ({
  jurisdiction,
  barNumber: barNumber as BarLookup['barNumber'],
});
const jurisdictions = { XA: 'XA-DM' };

let registry: Server;
let base: string;
beforeAll(async () => {
  registry = await startRegistry(0);
  base = `http://127.0.0.1:${(registry.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => registry.close(() => r())));

const demo = () => demoAdapter({ baseUrl: base, jurisdictions });

adapterContract('demo', async () => ({ adapter: demo(), active: q('DEMO-0001'), unknown: q('DEMO-9999') }));
adapterContract('manual', async () => {
  const adapter = manualAdapter();
  adapter.upload({
    jurisdiction: 'XA',
    barNumber: 'DEMO-0001',
    status: 'active',
    page: new TextEncoder().encode('<html>saved page</html>'),
    url: 'https://registry.example/lawyers',
  });
  return { adapter, active: q('DEMO-0001'), unknown: q('DEMO-9999') };
});

describe('P3.3-02 demo adapter against the mock registry', () => {
  it.each([
    ['DEMO-0001', 'active'],
    ['DEMO-0003', 'not_active'], // struck_off (OD-12)
    ['DEMO-0004', 'not_active'], // lapsed (OD-12)
    ['DEMO-7777', 'not_found'],
  ])('%s is %s', async (bar, status) => {
    expect((await demo().lookup(q(bar))).status).toBe(status);
  });
  it('hashes the exact response bytes as evidence', async () => {
    const r = await demo().lookup(q('DEMO-0002'));
    const raw = new Uint8Array(await (await fetch(`${base}/api/lawyers/XA-DM/DEMO-0002`)).arrayBuffer());
    expect(r.source.evidenceSha256).toBe(bytesToHex(sha256(raw)));
  });
});

describe('P3.3-03 manual adapter', () => {
  it('puts the SHA-256 of the uploaded page into evidenceSha256', async () => {
    const page = new TextEncoder().encode('saved registry page, version 1');
    const m = manualAdapter();
    m.upload({ jurisdiction: 'US-CA', barNumber: 'ab-123', status: 'active', page, url: 'https://calbar.example/x' });
    const r = await m.lookup(q('AB-123', 'US-CA'));
    expect(r.source).toEqual({
      kind: 'manual',
      url: 'https://calbar.example/x',
      evidenceSha256: bytesToHex(sha256(page)),
    });
    expect(r.status).toBe('active');
  });
  it('reports not_active as the operator recorded it', async () => {
    const m = manualAdapter();
    m.upload({
      jurisdiction: 'US-CA',
      barNumber: 'AB-1',
      status: 'not_active',
      page: new Uint8Array([1]),
      url: 'https://x.example/',
    });
    expect((await m.lookup(q('AB-1', 'US-CA'))).status).toBe('not_active');
  });
});

describe('P3.3-09 the mock registry says DEMO REGISTRY everywhere', () => {
  it.each([
    '/',
    '/lawyers/XA-DM/DEMO-0001',
    '/lawyers/XA-DM/DEMO-9999',
    '/api/lawyers/XA-DM/DEMO-0003',
    '/api/lawyers/XA-DM/DEMO-9999',
  ])('%s', async (path) => {
    const res = await fetch(base + path);
    const text = await res.text();
    expect(text).toContain('DEMO');
    if (path.startsWith('/api')) expect(JSON.parse(text).demo).toBe(true);
    else expect(text).toContain('DEMO REGISTRY');
  });
});

describe('a broken registry gives clean errors', () => {
  let bad: Server;
  let mode = 'hang';
  let baseBad: string;
  beforeAll(async () => {
    bad = createServer((req, res) => {
      if (mode === 'hang') return; // never answers
      if (mode === 'html') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<html><body><h1>Maintenance</h1><p>{"status": "act');
      } else if (mode === 'huge') {
        res.writeHead(200);
        res.write('x'.repeat(200_000));
        res.end();
      } else if (mode === 'lie') {
        res.writeHead(200);
        res.end(JSON.stringify({ jurisdiction: 'XA-DM', barNumber: 'DEMO-0002', status: 'active' }));
      } else if (mode === 'unknown-status') {
        res.writeHead(200);
        res.end(JSON.stringify({ jurisdiction: 'XA-DM', barNumber: 'DEMO-0001', status: 'suspended-pending' }));
      } else if (mode === 'redirect') {
        res.writeHead(302, { location: 'http://127.0.0.1:1/' });
        res.end();
      } else if (mode === 'html-404') {
        res.writeHead(404, { 'content-type': 'text/html' });
        res.end('<p>not here</p>');
      } else if (mode === 'drop') {
        req.socket.destroy();
      } else {
        res.writeHead(500);
        res.end('boom');
      }
    });
    await new Promise<void>((r) => bad.listen(0, '127.0.0.1', r));
    baseBad = `http://127.0.0.1:${(bad.address() as AddressInfo).port}`;
  });
  afterAll(() => {
    bad.closeAllConnections();
    return new Promise<void>((r) => bad.close(() => r()));
  });
  const bad1 = () => demoAdapter({ baseUrl: baseBad, jurisdictions, timeoutMs: 300, maxBytes: 4096 });

  it.each([
    ['hang', 'ADAPTER_TIMEOUT'],
    ['drop', 'ADAPTER_UNREACHABLE'],
    ['html', 'ADAPTER_BAD_RESPONSE'],
    ['huge', 'ADAPTER_BAD_RESPONSE'],
    ['lie', 'ADAPTER_BAD_RESPONSE'], // answers for another lawyer
    ['unknown-status', 'ADAPTER_BAD_RESPONSE'], // fails closed, never "active"
    ['redirect', 'ADAPTER_UNREACHABLE'],
    ['html-404', 'ADAPTER_BAD_RESPONSE'],
    ['500', 'ADAPTER_BAD_RESPONSE'],
  ])('%s gives %s', async (m, code) => {
    mode = m;
    await expect(bad1().lookup(q('DEMO-0001'))).rejects.toMatchObject({ name: 'VerifierError', code });
  });

  it('a registry that is not running gives ADAPTER_UNREACHABLE', async () => {
    const dead = demoAdapter({ baseUrl: 'http://127.0.0.1:1', timeoutMs: 300 });
    await expect(dead.lookup(q('DEMO-0001'))).rejects.toMatchObject({ code: 'ADAPTER_UNREACHABLE' });
  });
});
