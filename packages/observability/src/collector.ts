// The OpenTelemetry Collector config of DESIGN 8.6, rendered from the same allow-list the SDK uses. The redaction
// processor is fail-closed (`allow_all_keys: false`); it is beta for traces and alpha for logs, so the in-process
// exporter filter (exporter.ts) and T-A-32 also check what leaves the process.
// Source: https://pkg.go.dev/github.com/open-telemetry/opentelemetry-collector-contrib/processor/redactionprocessor
// Source: https://opentelemetry.io/docs/collector/configuration/
import { ALLOWED_ATTRIBUTES, BLOCKED_VALUES } from './allowlist.ts';

/** JSON strings are valid YAML double-quoted scalars, so they carry the regex escapes unchanged. */
const q = (s: string) => JSON.stringify(s);

export interface CollectorConfigOptions {
  /** Tests only: write spans as JSON lines to this file instead of the `debug` exporter. */
  readonly fileExporterPath?: string;
}

export function collectorConfig(options: CollectorConfigOptions = {}): string {
  const exporter = options.fileExporterPath ? 'file' : 'debug';
  const exporterBody = options.fileExporterPath
    ? `    path: ${q(options.fileExporterPath)}`
    : '    verbosity: detailed';
  return `# Generated from packages/observability/src/allowlist.ts by collectorConfig(); a test fails if this file drifts.
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

processors:
  redaction:
    allow_all_keys: false
    allowed_keys:
${ALLOWED_ATTRIBUTES.map((k) => `      - ${q(k)}`).join('\n')}
    blocked_values:
${BLOCKED_VALUES.map((b) => `      - ${q(b.pattern)}`).join('\n')}
    hash_function: hmac-sha256
    # The key must be at least 32 bytes for hmac-sha256 (the Collector refuses to start otherwise).
    hmac_key: "\${env:LEGX_REDACTION_HMAC_KEY}"
    summary: info

exporters:
  ${exporter}:
${exporterBody}

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [redaction]
      exporters: [${exporter}]
`;
}
