// OpenTelemetry Node SDK setup (2.x line: sdk-node 0.223, auto-instrumentations 0.81, see IMPLEMENTATION 4.3).
// Only W3C Trace Context is propagated, never Baggage: `deal.id` is copied into span attributes on purpose (spans.ts) and
// no baggage header can leave the process (DESIGN 8.6: baggage can leak to third parties and has no integrity check).
// Source: https://opentelemetry.io/docs/languages/js/getting-started/nodejs/
// Source: https://www.w3.org/TR/trace-context-2/ and https://opentelemetry.io/docs/concepts/signals/baggage/

import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { W3CTraceContextPropagator } from '@opentelemetry/core';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { BatchSpanProcessor, SimpleSpanProcessor, type SpanExporter } from '@opentelemetry/sdk-trace';
import { AllowListSpanExporter } from './exporter.ts';

export interface TelemetryOptions {
  readonly serviceName: string;
  /** Default: OTLP over HTTP to the Collector (`OTEL_EXPORTER_OTLP_ENDPOINT`). Tests pass an in-memory exporter. */
  readonly exporter?: SpanExporter;
  /** `simple` exports each span at once (tests); `batch` is for production. */
  readonly processor?: 'simple' | 'batch';
}

export interface Telemetry {
  shutdown(): Promise<void>;
}

/** Starts the SDK with auto-instrumentation. Every exporter, including the default one, sits behind the allow-list. */
export function startTelemetry(options: TelemetryOptions): Telemetry {
  const exporter = new AllowListSpanExporter(options.exporter ?? new OTLPTraceExporter());
  const sdk = new NodeSDK({
    serviceName: options.serviceName,
    spanProcessors: [
      options.processor === 'simple' ? new SimpleSpanProcessor({ exporter }) : new BatchSpanProcessor({ exporter }),
    ],
    textMapPropagator: new W3CTraceContextPropagator(),
    instrumentations: [getNodeAutoInstrumentations({ '@opentelemetry/instrumentation-fs': { enabled: false } })],
  });
  sdk.start();
  return { shutdown: () => sdk.shutdown() };
}
