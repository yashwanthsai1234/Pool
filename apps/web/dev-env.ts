// Dev-server defaults from the demo seeding (OD-31): the observer key that `scripts/demo/seed.ts` wrote to `demo/state.json`
// and the standalone ledger's JSON-RPC port. Plain Node, imported by vite.config.ts. A build and the production profile get
// nothing: an observer key must never be baked into a bundle, and the user's own settings win.
// Source: https://vite.dev/guide/env-and-mode (VITE_ variables from the process environment reach import.meta.env)
type Ctx = { command: 'serve' | 'build'; env: Record<string, string | undefined> };

export function devEnvFromDemoState(stateJson: string | undefined, ctx: Ctx): Record<string, string> {
  if (ctx.command !== 'serve' || ctx.env.VITE_LEGX_PROFILE === 'production' || stateJson === undefined) return {};
  let state: { network?: string; observer?: { keyId?: string; ed25519Private?: string; mlDsa65Private?: string } };
  try {
    state = JSON.parse(stateJson);
  } catch {
    return {};
  }
  const out: Record<string, string> = {};
  const o = state.observer;
  if (ctx.env.VITE_LEGX_OBSERVER === undefined && o?.keyId && o.ed25519Private && o.mlDsa65Private)
    out.VITE_LEGX_OBSERVER = JSON.stringify({
      keyId: o.keyId,
      ed25519Pkcs8: o.ed25519Private,
      mlDsa65Pkcs8: o.mlDsa65Private,
    });
  if (ctx.env.VITE_LEGX_XRPL_RPC === undefined && state.network === 'standalone')
    out.VITE_LEGX_XRPL_RPC = `http://127.0.0.1:${ctx.env.LEGX_LEDGER_PORT ?? 6113}`;
  return out;
}
