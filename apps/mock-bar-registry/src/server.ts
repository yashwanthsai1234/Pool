// Source: https://nodejs.org/api/http.html
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { DEMO_BANNER, findLawyer, type Lawyer } from './data.ts';

// Same pattern as the contract Jurisdiction (I-2). Path segments are checked against allow-lists before use, so `..`, `%`, and long input never reach the lookup.
const JURISDICTION = /^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/;
const BAR_NUMBER = /^[A-Za-z0-9-]{1,20}$/;
const MAX_PATH = 200;

type Route =
  | { kind: 'home' }
  | { kind: 'page' | 'api'; jurisdiction: string; barNumber: string }
  | { kind: 'bad' }
  | { kind: 'missing' };

// Source: https://nodejs.org/api/http.html#messageurl (req.url is the raw request target, so it is parsed here and not normalised)
function parseRoute(target: string): Route {
  const path = target.split('?')[0] ?? '';
  if (path === '/') return { kind: 'home' };
  if (path.length > MAX_PATH) return { kind: 'bad' };
  const api = path.startsWith('/api/lawyers/');
  const prefix = api ? '/api/lawyers/' : '/lawyers/';
  if (!api && !path.startsWith(prefix)) return { kind: 'missing' };
  const [jurisdiction, barNumber, ...rest] = path.slice(prefix.length).split('/');
  if (jurisdiction === undefined || barNumber === undefined || rest.length > 0) return { kind: 'bad' };
  if (!JURISDICTION.test(jurisdiction) || !BAR_NUMBER.test(barNumber)) return { kind: 'bad' };
  return { kind: api ? 'api' : 'page', jurisdiction, barNumber };
}

// Source: https://nodejs.org/api/http.html#responsewriteheadstatuscode-statusmessage-headers
function sendHtml(res: ServerResponse, status: number, title: string, body: string): void {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title} - Demo Registry</title></head>` +
      `<body><p class="banner"><strong>${DEMO_BANNER}</strong></p><h1>${title}</h1>${body}</body></html>`,
  );
}

function sendJson(res: ServerResponse, status: number, body: Record<string, unknown>): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ demo: true, ...body }));
}

function lawyerHtml(lawyer: Lawyer): string {
  return (
    `<dl><dt>Name</dt><dd>${lawyer.name}</dd><dt>Jurisdiction</dt><dd>${lawyer.jurisdiction}</dd>` +
    `<dt>Bar number</dt><dd>${lawyer.barNumber}</dd><dt>Status</dt><dd>${lawyer.status}</dd></dl>`
  );
}

// Source: https://nodejs.org/api/http.html#event-request
function handle(req: IncomingMessage, res: ServerResponse): void {
  try {
    route(req, res);
  } catch {
    // A handler error must not take the process down. Headers may already be sent, so end the response if so.
    if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('internal error');
  }
}

// Source: https://nodejs.org/api/http.html#class-httpserver
function route(req: IncomingMessage, res: ServerResponse): void {
  if (req.method !== 'GET') {
    res.setHeader('allow', 'GET');
    sendHtml(res, 405, 'Method not allowed', '<p>Only GET is supported.</p>');
    return;
  }
  const target = parseRoute(req.url ?? '/');
  if (target.kind === 'home') {
    const links = ['DEMO-0001', 'DEMO-0002', 'DEMO-0003', 'DEMO-0004']
      .map((bar) => `<li><a href="/lawyers/XA-DM/${bar}">XA-DM ${bar}</a></li>`)
      .join('');
    sendHtml(res, 200, 'Demo bar registry', `<ul>${links}</ul>`);
    return;
  }
  if (target.kind === 'missing') {
    sendHtml(res, 404, 'Page not found', '<p>No such page.</p>');
    return;
  }
  if (target.kind === 'bad') {
    if ((req.url ?? '').startsWith('/api/')) sendJson(res, 400, { error: 'invalid_request' });
    else sendHtml(res, 400, 'Invalid request', '<p>Invalid jurisdiction or bar number.</p>');
    return;
  }
  const lawyer = findLawyer(target.jurisdiction, target.barNumber);
  if (target.kind === 'api') {
    if (lawyer === undefined) {
      sendJson(res, 404, { jurisdiction: target.jurisdiction, barNumber: target.barNumber, status: 'not_found' });
    } else {
      sendJson(res, 200, { ...lawyer });
    }
    return;
  }
  if (lawyer === undefined) sendHtml(res, 404, 'Lawyer not found', '<p>status: not_found</p>');
  else sendHtml(res, 200, 'Lawyer', lawyerHtml(lawyer));
}

// Binds to 127.0.0.1 only. Resolves once the server is listening (use port 0 for an ephemeral port in tests).
export function startRegistry(port: number): Promise<Server> {
  const server = createServer(handle);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server);
    });
  });
}
