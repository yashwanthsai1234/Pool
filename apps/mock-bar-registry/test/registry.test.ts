import type { Server } from 'node:http';
import { request } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DEMO_BANNER } from '../src/data.ts';
import { startRegistry } from '../src/index.ts';

let server: Server;

beforeAll(async () => {
  server = await startRegistry(0);
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no port');
});

afterAll(() => {
  server.close();
});

// Raw request: the Node client does not normalise `../`, so hostile paths reach the server unchanged.
function raw(method: string, path: string): Promise<{ status: number; type: string; body: string }> {
  const { port } = server.address() as { port: number };
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method, path }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => {
        body += chunk;
      });
      res.on('end', () => {
        resolve({ status: res.statusCode ?? 0, type: res.headers['content-type'] ?? '', body });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

const json = (body: string): Record<string, unknown> => JSON.parse(body) as Record<string, unknown>;

describe('I-2 jurisdiction code', () => {
  it('every demo jurisdiction is a valid contract Jurisdiction, and a long subdivision is refused', async () => {
    const { LAWYERS } = await import('../src/data.ts');
    // Same pattern as packages/contracts `Jurisdiction` (values.ts); the registry has no dependency on contracts.
    const Jurisdiction = /^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/;
    for (const l of LAWYERS) expect(Jurisdiction.test(l.jurisdiction)).toBe(true);
    expect((await raw('GET', '/api/lawyers/XA-DEMO/DEMO-0001')).status).toBe(400);
  });
});

describe('lawyer statuses', () => {
  it.each([
    ['DEMO-0001', 'active'],
    ['DEMO-0002', 'active'],
    ['DEMO-0003', 'struck_off'],
    ['DEMO-0004', 'lapsed'],
  ])('JSON for %s reports %s', async (barNumber, status) => {
    const res = await raw('GET', `/api/lawyers/XA-DM/${barNumber}`);
    expect(res.status).toBe(200);
    expect(res.type).toContain('application/json');
    expect(json(res.body)).toMatchObject({ jurisdiction: 'XA-DM', barNumber, status });
  });

  it('HTML page shows the status of a lawyer', async () => {
    const res = await raw('GET', '/lawyers/XA-DM/DEMO-0003');
    expect(res.status).toBe(200);
    expect(res.type).toContain('text/html');
    expect(res.body).toContain('struck_off');
  });
});

describe('not_found', () => {
  it('unknown bar number returns status not_found with HTTP 404', async () => {
    const res = await raw('GET', '/api/lawyers/XA-DM/DEMO-9999');
    expect(res.status).toBe(404);
    expect(json(res.body)).toMatchObject({ barNumber: 'DEMO-9999', status: 'not_found' });
  });

  it('unknown bar number HTML page returns 404 and says not found', async () => {
    const res = await raw('GET', '/lawyers/XA-DM/DEMO-9999');
    expect(res.status).toBe(404);
    expect(res.body).toContain('not_found');
  });
});

describe('demo banner and flag', () => {
  const htmlPaths = ['/', '/lawyers/XA-DM/DEMO-0001', '/lawyers/XA-DM/DEMO-9999', '/lawyers/XA-DM/bad..x', '/nope'];
  const jsonPaths = ['/api/lawyers/XA-DM/DEMO-0001', '/api/lawyers/XA-DM/DEMO-9999', '/api/lawyers/../x'];

  it.each(htmlPaths)('HTML %s shows the demo banner', async (path) => {
    const res = await raw('GET', path);
    expect(res.type).toContain('text/html');
    expect(res.body).toContain(DEMO_BANNER);
  });

  it.each(jsonPaths)('JSON %s carries demo: true', async (path) => {
    const res = await raw('GET', path);
    expect(res.type).toContain('application/json');
    expect(json(res.body).demo).toBe(true);
  });
});

describe('hostile input', () => {
  it.each([
    '/api/lawyers/../../etc/passwd',
    '/api/lawyers/XA-DM/..%2F..%2Fsecret',
    '/api/lawyers/XA-DM/%00',
    '/lawyers/XA-DM/DEMO-0001/extra',
    `/lawyers/XA-DM/${'A'.repeat(5000)}`,
    `/api/lawyers/${'X'.repeat(5000)}/DEMO-0001`,
  ])('%s gets 400 and the server keeps running', async (path) => {
    const res = await raw('GET', path);
    expect(res.status).toBe(400);
    const healthy = await raw('GET', '/');
    expect(healthy.status).toBe(200);
  });

  it('a bad API path returns a JSON error with the demo flag', async () => {
    const res = await raw('GET', '/api/lawyers/../../etc/passwd');
    expect(json(res.body)).toMatchObject({ error: 'invalid_request', demo: true });
  });

  it('a request line beyond the Node header limit does not crash the server', async () => {
    const res = await raw('GET', `/api/lawyers/${'A'.repeat(20_000)}`);
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    expect((await raw('GET', '/')).status).toBe(200);
  });

  it('non-GET methods get 405', async () => {
    const res = await raw('POST', '/api/lawyers/XA-DM/DEMO-0001');
    expect(res.status).toBe(405);
  });
});
