// Starts MSW in a browser (tests and `vite dev`). Never imported by the production entry.
// Source: https://mswjs.io/docs/api/setup-worker/start (onUnhandledFrame, quiet, serviceWorker.url)
import type { AnyHandler } from 'msw';
import { setupWorker } from 'msw/browser';

export async function startMocks(...handlers: AnyHandler[]) {
  const worker = setupWorker(...handlers);
  await worker.start({ quiet: true, onUnhandledFrame: 'bypass' });
  return worker;
}
