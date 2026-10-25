// The attribute allow-list and the blocked-value patterns of DESIGN 8.6, in one place. The OTel Collector config
// (`collector.ts`), the in-process exporter filter and the span helper all read these, so they cannot drift apart.
// Source: https://pkg.go.dev/github.com/open-telemetry/opentelemetry-collector-contrib/processor/redactionprocessor

/** Span attribute keys that may leave the process. Everything else is dropped (fail closed). */
export const ALLOWED_ATTRIBUTES = [
  'deal.id',
  'deal.state',
  'deal.phase',
  'xrpl.tx_hash',
  'xrpl.ledger_index',
  'xrpl.engine_result',
  'http.route',
  'http.response.status_code',
  'gate.result',
  'gate.finding_code',
  'attest.side',
  'attest.result',
  'attest.chip_auth',
  'bar.result',
  'bar.source_kind',
  'credential.result',
] as const;
export type AllowedAttribute = (typeof ALLOWED_ATTRIBUTES)[number];

const ALLOWED = new Set<string>(ALLOWED_ATTRIBUTES);
export const isAllowedAttribute = (key: string): boolean => ALLOWED.has(key);

/** Value patterns that are masked even under an allowed key: DESIGN 8.6 plus two "looks like raw bytes" rules. */
export const BLOCKED_VALUES: readonly { readonly name: string; readonly pattern: string }[] = [
  { name: 'email', pattern: '[\\w.+-]+@[\\w-]+\\.[\\w.]+' },
  { name: 'xrpl-family-seed', pattern: '\\bs[1-9A-HJ-NP-Za-km-z]{25,}\\b' },
  { name: 'mrz-line-1', pattern: 'P<[A-Z<]{5,}' },
  { name: 'mrz-line-2', pattern: '[A-Z0-9<]{9}[0-9][A-Z<]{3}[0-9]{6}' },
  // Not in DESIGN 8.6; added because DG1 bytes and keys travel as hex or base64, which the MRZ patterns cannot see.
  { name: 'long-hex', pattern: '\\b[0-9a-fA-F]{128,}\\b' },
  { name: 'long-base64', pattern: '[A-Za-z0-9+/]{120,}={0,2}' },
  { name: 'pem', pattern: '-----BEGIN [A-Z ]+-----' },
];

const BLOCKED = BLOCKED_VALUES.map((b) => new RegExp(b.pattern, 'g'));
export const REDACTED = '[REDACTED]';

/** Masks every blocked pattern in `s`. */
export function scrubString(s: string): string {
  let out = s;
  for (const re of BLOCKED) out = out.replace(re, REDACTED);
  return out;
}
