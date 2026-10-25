// The process entry (`pnpm dev`, `node apps/server/src/main.ts`). The profile comes from LEGX_PROFILE; unset means
// production, and production refuses to start with any demo port configured (P3.7-05, P3.7-07).
import { buildServer } from './compose.ts';
import { assertNotSepoliaChain, assertProfile, profileFromEnv } from './config.ts';
import { buildDemo } from './demo.ts';
import { buildProduction } from './production.ts';

export async function start(env: Readonly<Record<string, string | undefined>> = process.env) {
  const profile = profileFromEnv(env);
  // Refuse first, before any connection is opened.
  assertProfile({ profile, ports: {}, env });
  await assertNotSepoliaChain(
    profile,
    (env.LEGX_ZK_RPC ?? '')
      .split(',')
      .map((u) => u.trim())
      .filter(Boolean),
  );
  const built = await (profile === 'production' ? buildProduction(env) : buildDemo(env));
  try {
    const server = await buildServer(built.deps);
    const port = Number(env.LEGX_PORT ?? 8710);
    await server.app.listen({ port, host: env.LEGX_HOST ?? '127.0.0.1' });
    return {
      port,
      server,
      stop: async () => {
        await server.close();
        await built.stop();
      },
    };
  } catch (e) {
    await built.stop();
    throw e;
  }
}

if (import.meta.main) {
  try {
    const s = await start();
    process.stderr.write(`legx server (${profileFromEnv(process.env)}) listening on http://127.0.0.1:${s.port}\n`);
    for (const sig of ['SIGINT', 'SIGTERM'] as const)
      process.once(sig, () => void s.stop().finally(() => process.exit(0)));
  } catch (e) {
    process.stderr.write(`legx server: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
  }
}
