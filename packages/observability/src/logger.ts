// pino with redaction built from the contracts: every field marked `Secret<>` in any contract schema (their JSON Schema
// carries `x-legx-secret`) becomes a redact path, matched by leaf name at any depth; objects pass through a deep scrub
// that masks those keys, byte arrays, and the blocked value patterns of DESIGN 8.6. Trace and span IDs are added from the
// active span so that logs and traces join up.
// Source: https://getpino.io/#/docs/redaction and https://github.com/davidmarkclements/fast-redact
// Source: https://opentelemetry.io/docs/specs/otel/compatibility/logging_trace_context/
import { SCHEMAS } from '@legx/contracts/catalog';
import { secretPaths } from '@legx/contracts/secret';
import { trace } from '@opentelemetry/api';
import pino, { type DestinationStream, type Logger } from 'pino';
import { REDACTED, scrubString } from './allowlist.ts';

/** Field names that hold secrets in internal (non-contract) objects: salts, seeds, keys, raw passport data. */
const STATIC_SECRET_KEYS = [
  'salt',
  'seed',
  'secret',
  'secretKey',
  'privateKey',
  'sharedSecret',
  'signingShare',
  'preimage',
  'mnemonic',
  'dg1',
  'dg2',
  'dg14',
  'dg15',
  'sod',
  'mrz',
  'password',
  'authorization',
  'cookie',
];

/** JSON-pointer secret paths (`/request/queryResult`) of every contract schema, deduplicated. */
export function contractSecretPaths(): string[] {
  return [...new Set(Object.values(SCHEMAS).flatMap((s) => secretPaths(s)))].sort();
}

/** Leaf names of the secret paths plus the static list: the keys the deep scrub masks at any depth. */
export function secretKeyNames(): Set<string> {
  const leaves = contractSecretPaths().map(
    (p) =>
      p
        .split('/')
        .filter((x) => x && x !== '*')
        .at(-1) ?? '',
  );
  return new Set([...leaves, ...STATIC_SECRET_KEYS].filter(Boolean).map((k) => k.toLowerCase()));
}

/** pino `redact.paths`: each secret as a top-level key, one level down, and by its full dotted path. */
export function redactPaths(): string[] {
  const out = new Set<string>();
  for (const p of contractSecretPaths()) {
    const dotted = p
      .split('/')
      .filter(Boolean)
      .map((x) => (x === '*' ? '[*]' : x))
      .join('.')
      .replaceAll('.[*]', '[*]');
    out.add(dotted);
    out.add(`*.${dotted}`);
  }
  for (const k of secretKeyNames()) {
    out.add(k);
    out.add(`*.${k}`);
  }
  return [...out].sort();
}

const MAX_DEPTH = 10;

/** Copies `value` with secret keys masked, byte arrays summarized and strings scrubbed. Cycles and depth are bounded. */
export function scrubDeep(value: unknown, secrets: ReadonlySet<string>, depth = 0): unknown {
  if (typeof value === 'string') return scrubString(value);
  if (typeof value === 'bigint') return value.toString();
  if (value === null || typeof value !== 'object') return value;
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return `[${value.byteLength} bytes]`;
  if (depth >= MAX_DEPTH) return '[too deep]';
  if (Array.isArray(value)) return value.map((v) => scrubDeep(v, secrets, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = secrets.has(k.toLowerCase()) ? REDACTED : scrubDeep(v, secrets, depth + 1);
  }
  return out;
}

export interface LoggerOptions {
  readonly level?: string;
  readonly destination?: DestinationStream;
}

export function createLogger(options: LoggerOptions = {}): Logger {
  const secrets = secretKeyNames();
  const serializeError = (e: unknown) => {
    const err = e instanceof Error ? e : new Error(String(e));
    return { type: err.name, message: scrubString(err.message), stack: err.stack ? scrubString(err.stack) : undefined };
  };
  return pino(
    {
      level: options.level ?? 'info',
      redact: { paths: redactPaths(), censor: REDACTED },
      formatters: { log: (obj) => scrubDeep(obj, secrets) as Record<string, unknown> },
      serializers: { err: serializeError, error: serializeError },
      hooks: {
        // The message string and any printf-style arguments are scrubbed too.
        logMethod(args, method) {
          method.apply(
            this,
            args.map((a) => (typeof a === 'string' ? scrubString(a) : a)) as Parameters<typeof method>,
          );
        },
      },
      mixin() {
        const ctx = trace.getActiveSpan()?.spanContext();
        return ctx ? { trace_id: ctx.traceId, span_id: ctx.spanId } : {};
      },
    },
    options.destination,
  );
}
