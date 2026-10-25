// Polls the standalone ledger's admin WebSocket until server_info answers (P2.1-01). Exit 1 after 60 s.
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/server-info-methods/server_info
import xrpl from 'xrpl';

const url = process.env.XRPLD_WS ?? `ws://127.0.0.1:${process.env.LEGX_LEDGER_PORT ?? '6101'}`;
const deadline = Date.now() + 60_000;

for (;;) {
  const client = new xrpl.Client(url, { timeout: 3000 });
  try {
    await client.connect();
    await client.request({ command: 'server_info' });
    await client.disconnect();
    process.stdout.write(`ledger ready at ${url}\n`);
    break;
  } catch {
    await client.disconnect().catch(() => undefined);
    if (Date.now() > deadline) {
      process.stderr.write(`ledger not ready at ${url} after 60 s\n`);
      process.exit(1);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}
