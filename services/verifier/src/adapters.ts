// Bar registry adapters (DESIGN 6.16): `manual` (an operator saves the registry page) and `demo` (the mock registry,
// apps/mock-bar-registry). Both return only {status, source}; the bar number never enters the result or the URL.
// OD-12: the demo adapter maps the registry's `struck_off` and `lapsed` to `not_active`.
import type { BarLookup, BarLookupResult, BarRegistryAdapter } from '@legx/contracts/ports';
import { Hex32 } from '@legx/contracts/values';
import { barNumberSha256, normalizeBarNumber } from '@legx/core/bar';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { z } from 'zod';
import { VerifierError } from './errors.ts';

const evidenceOf = (bytes: Uint8Array) => Hex32.parse(bytesToHex(sha256(bytes)));

function checkedNumber(q: BarLookup): string {
  try {
    return normalizeBarNumber(q.barNumber);
  } catch (e) {
    throw new VerifierError('ADAPTER_BAD_REQUEST', (e as Error).message);
  }
}

export interface ManualUpload {
  readonly jurisdiction: string;
  readonly barNumber: string;
  /** What the operator read from the saved page or PDF. */
  readonly status: BarLookupResult['status'];
  /** The saved registry page or PDF, exact bytes. Its SHA-256 becomes `evidence_sha256`. */
  readonly page: Uint8Array;
  readonly url: string;
}

/** The operator path: nothing is scraped. Uploads are keyed by jurisdiction and the bar number's SHA-256 only. */
export function manualAdapter(): BarRegistryAdapter & { upload(u: ManualUpload): void } {
  const uploads = new Map<string, BarLookupResult>();
  const key = (jurisdiction: string, barNumber: string) => `${jurisdiction}:${barNumberSha256(barNumber)}`;
  return {
    name: 'manual',
    upload(u) {
      uploads.set(key(u.jurisdiction, u.barNumber), {
        status: u.status,
        source: { kind: 'manual', url: u.url, evidenceSha256: evidenceOf(u.page) },
      });
    },
    async lookup(q) {
      const found = uploads.get(key(q.jurisdiction, checkedNumber(q)));
      if (found) return found;
      return {
        status: 'not_found',
        source: {
          kind: 'manual',
          url: 'https://manual.invalid/no-upload',
          evidenceSha256: evidenceOf(new Uint8Array()),
        },
      };
    },
  };
}

const DemoLawyer = z.object({
  jurisdiction: z.string(),
  barNumber: z.string(),
  status: z.enum(['active', 'struck_off', 'lapsed']),
});

export interface DemoAdapterOptions {
  readonly baseUrl: string;
  /** Our jurisdiction code to the registry's own key (for a registry whose own key differs from ours). */
  readonly jurisdictions?: Readonly<Record<string, string>>;
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
  readonly fetch?: typeof fetch;
}

// Reads at most `max` bytes, so a hostile or broken registry cannot make us buffer without limit.
async function readCapped(res: Response, max: number): Promise<Uint8Array> {
  const reader = res.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel();
      throw new VerifierError('ADAPTER_BAD_RESPONSE', `registry response is larger than ${max} bytes`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

/** The demo adapter: GET `/api/lawyers/<jurisdiction>/<barNumber>` on the mock registry. Fails closed on anything odd. */
// Source: https://developer.mozilla.org/en-US/docs/Web/API/AbortSignal/timeout_static
export function demoAdapter(o: DemoAdapterOptions): BarRegistryAdapter {
  const doFetch = o.fetch ?? fetch;
  const timeoutMs = o.timeoutMs ?? 5000;
  const maxBytes = o.maxBytes ?? 64 * 1024;
  const root = new URL('/api/lawyers/', o.baseUrl);
  return {
    name: 'demo',
    async lookup(q) {
      const barNumber = checkedNumber(q);
      const registryKey = o.jurisdictions?.[q.jurisdiction] ?? q.jurisdiction;
      const url = new URL(`${encodeURIComponent(registryKey)}/${encodeURIComponent(barNumber)}`, root);
      let res: Response;
      let body: Uint8Array;
      try {
        res = await doFetch(url, { signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
        body = await readCapped(res, maxBytes);
      } catch (e) {
        if (e instanceof VerifierError) throw e;
        const timedOut = e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError');
        throw new VerifierError(timedOut ? 'ADAPTER_TIMEOUT' : 'ADAPTER_UNREACHABLE', 'registry did not answer');
      }
      // The URL names the registry, not the lawyer: the bar number is never written into a signed record.
      const source = { kind: 'registry-api', url: root.href, evidenceSha256: evidenceOf(body) } as const;
      const json = parseJson(body);
      if (res.status === 404 && (json as { status?: unknown } | undefined)?.status === 'not_found') {
        return { status: 'not_found', source };
      }
      const lawyer = res.status === 200 ? DemoLawyer.safeParse(json) : undefined;
      if (!lawyer?.success || lawyer.data.barNumber !== barNumber || lawyer.data.jurisdiction !== registryKey) {
        throw new VerifierError('ADAPTER_BAD_RESPONSE', `registry answered ${res.status} with an unusable body`);
      }
      return { status: lawyer.data.status === 'active' ? 'active' : 'not_active', source };
    },
  };
}

function parseJson(body: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    return undefined;
  }
}
