// startTelemetry with the real NodeSDK: the global tracer exports through the allow-list, and only W3C Trace Context is
// propagated (no baggage can leave the process).
// Not tested here: auto-instrumentation of `node:http`. Under ESM it needs the import-in-the-middle loader hook
// (`node --import @opentelemetry/instrumentation/hook.mjs` before the app), which a Vitest worker cannot provide; the
// server entry point (task 3.7) must register it. Whatever it records still passes through the exporter filter tested here.
import { context, propagation, ROOT_CONTEXT, trace } from '@opentelemetry/api';
import { InMemorySpanExporter } from '@opentelemetry/sdk-trace';
import { describe, expect, it } from 'vitest';
import { startTelemetry } from '../src/setup.ts';

describe('startTelemetry', () => {
  it('exports spans from the global tracer through the allow-list, and propagates trace context but not baggage', async () => {
    const memory = new InMemorySpanExporter();
    const telemetry = startTelemetry({ serviceName: 'legx-test', exporter: memory, processor: 'simple' });
    const span = trace.getTracer('test').startSpan('legx.ops.bind', {
      attributes: { 'deal.id': 'd1', 'http.url': 'https://x/?token=secret', 'user.email': 'a@b.example' },
    });
    span.end();

    const carrier: Record<string, string> = {};
    const withBaggage = propagation.setBaggage(
      trace.setSpan(ROOT_CONTEXT, trace.getTracer('test').startSpan('carrier')),
      propagation.createBaggage({ 'deal.id': { value: 'd1' } }),
    );
    propagation.inject(withBaggage, carrier);

    const find = () => memory.getFinishedSpans().find((s) => s.name === 'legx.ops.bind');
    for (let i = 0; i < 50 && !find(); i++) await new Promise((r) => setTimeout(r, 100)); // resource detection is async
    const exported = find(); // shutdown clears the exporter
    await telemetry.shutdown();
    expect(exported?.attributes).toEqual({ 'deal.id': 'd1' });
    expect(Object.keys(carrier)).toEqual(['traceparent']);
    expect(context.active()).toBe(ROOT_CONTEXT);
  }, 60_000);
});
