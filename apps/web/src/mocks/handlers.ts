// MSW REST handlers generated from the contracts route table: one handler per route, answering with the
// first golden output example (or an override). Every request must carry a well-formed `x-legx-auth` header,
// as the real server demands (DESIGN 8.10), so a client that forgets to sign fails here too.
// Source: https://mswjs.io/docs/api/http (http.get/post, path params `:name`, HttpResponse.json)
import { API_AUTH_HEADER, ApiAuth } from '@legx/contracts/api';
import { listRoutes } from '@legx/contracts/catalog';
import { type HttpHandler, HttpResponse, http } from 'msw';
import { API_BASE } from '../lib/paths.ts';
import { examplesOf } from './examples.ts';

export interface RecordedRequest {
  readonly route: string;
  readonly method: string;
  /** Path and query as received. */
  readonly path: string;
  readonly auth: unknown;
  readonly body: Uint8Array;
}

export interface RestMockOptions {
  /** Route name (for example `deals.get`) to the JSON the mock answers with. */
  responses?: Record<string, unknown>;
  onRequest?: (request: RecordedRequest) => void;
}

const HTTP_METHODS = { GET: http.get, POST: http.post } as const;

export function restHandlers(options: RestMockOptions = {}): HttpHandler[] {
  return listRoutes().map((route) => {
    const method = HTTP_METHODS[route.method as keyof typeof HTTP_METHODS];
    if (!method || !route.path) throw new Error(`route ${route.name} has no GET or POST path`);
    const response = options.responses?.[route.name] ?? examplesOf(`route.${route.name}.output`)[0];
    return method(`*${API_BASE}${route.path.replace(/\{(\w+)\}/g, ':$1')}`, async ({ request }) => {
      const raw = request.headers.get(API_AUTH_HEADER);
      const auth = ApiAuth.safeParse(raw === null ? undefined : safeJson(raw));
      if (!auth.success)
        return HttpResponse.json({ code: 'UNAUTHORIZED', message: 'bad x-legx-auth' }, { status: 401 });
      const { pathname, search } = new URL(request.url);
      options.onRequest?.({
        route: route.name,
        method: request.method,
        path: pathname + search,
        auth: auth.data,
        body: new Uint8Array(await request.arrayBuffer()),
      });
      return HttpResponse.json(response as Record<string, unknown>);
    });
  });
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
