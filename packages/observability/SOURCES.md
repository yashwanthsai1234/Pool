# Sources (task 3.6, observability)

- DESIGN 8.6 (spans, allow-list, blocked values) is the spec for `allowlist.ts`, `spans.ts` and `collector.ts`.
- OTel Collector redaction processor (allowed_keys, blocked_values, hash_function, hmac_key): https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/redactionprocessor/README.md , https://pkg.go.dev/github.com/open-telemetry/opentelemetry-collector-contrib/processor/redactionprocessor
- OTel Collector configuration (`${env:VAR}`): https://opentelemetry.io/docs/collector/configuration/
- OTel JS Node getting started (NodeSDK): https://opentelemetry.io/docs/languages/js/getting-started/nodejs/
- OTel span exporter interface: https://opentelemetry.io/docs/specs/otel/trace/sdk/#span-exporter
- OTel exceptions on spans (we skip recordException on purpose): https://opentelemetry.io/docs/specs/otel/trace/exceptions/
- OTel log and trace correlation: https://opentelemetry.io/docs/specs/otel/compatibility/logging_trace_context/
- W3C Trace Context and OTel baggage warning: https://www.w3.org/TR/trace-context-2/ , https://opentelemetry.io/docs/concepts/signals/baggage/
- pino redaction: https://getpino.io/#/docs/redaction , fast-redact: https://github.com/davidmarkclements/fast-redact
- `@opentelemetry/sdk-trace-base` 2.12.0 is deprecated in favour of `@opentelemetry/sdk-trace` (npm deprecation notice); this package uses `@opentelemetry/sdk-trace`.
