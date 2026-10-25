// The typed API client, generated from the `@legx/contracts` route table (P4.1-02).
// Source: https://orpc.dev/docs/openapi/client/openapi-link (OpenAPILink + createORPCClient, contract-first)
// Source: https://orpc.dev/docs/client/server-side#contract-first (type: ContractRouterClient)

import { contract } from '@legx/contracts';
import { API_AUTH_HEADER, type ApiAuth } from '@legx/contracts/api';
import { createORPCClient } from '@orpc/client';
import type { ContractRouterClient } from '@orpc/contract';
import type { JsonifiedClient } from '@orpc/openapi-client';
import { OpenAPILink } from '@orpc/openapi-client/fetch';
import type { z } from 'zod';
import { API_BASE } from './paths.ts';
/** What the key vault (task 4.2) is asked to sign: DESIGN 8.10, `tupleHash("legx/api-request/v1", [method, path, SHA-256(body), nonce, ledgerIndex])`. */
export interface SignableRequest {
  readonly method: string;
  /** Path and query as the server receives them: the proxy's API prefix is removed. */
  readonly path: string;
  /** The raw body bytes (empty for a GET). The signer hashes them. */
  readonly body: Uint8Array;
}

/** Returns the `x-legx-auth` value: a fresh nonce, a ledger index and the hybrid signatures. Supplied by the key vault. */
type SignRequest = (req: SignableRequest) => Promise<z.infer<typeof ApiAuth>>;

export type ApiClient = JsonifiedClient<ContractRouterClient<typeof contract>>;

export interface ApiClientOptions {
  signRequest: SignRequest;
  /** Default: the current origin. */
  origin?: string;
  /** Default: `API_BASE`. */
  prefix?: string;
  fetch?: typeof globalThis.fetch;
}

/** Every route is a signed request (DESIGN 8.10), so every call goes through `signRequest`; a failing signer sends nothing. */
export function createApiClient(options: ApiClientOptions): ApiClient {
  const doFetch = options.fetch ?? ((request: Request) => globalThis.fetch(request));
  const link = new OpenAPILink(contract, {
    url: `${options.origin ?? globalThis.location.origin}${options.prefix ?? API_BASE}`,
    fetch: async (request) => {
      const body = new Uint8Array(await request.clone().arrayBuffer());
      const { pathname, search } = new URL(request.url);
      // The reverse proxy strips the prefix, so the server verifies the path without it (OD-8: the path as the server receives it).
      const prefix = options.prefix ?? API_BASE;
      const path = (pathname.startsWith(prefix) ? pathname.slice(prefix.length) : pathname) + search;
      const auth = await options.signRequest({ method: request.method, path, body });
      const headers = new Headers(request.headers);
      headers.set(API_AUTH_HEADER, JSON.stringify(auth));
      return doFetch(new Request(request, { headers }));
    },
  });
  return createORPCClient(link);
}
