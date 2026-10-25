// Bundles the CLI and every dependency into one file, dist/verify.js, that runs on a bare Node 24 with no node_modules
// (DESIGN 8.8 item 12: an arbitrator may run it years later). The bundle goes inside the evidence bundle as `verify.js`.
// Source: https://esbuild.github.io/api/#build
import { build, type Plugin } from 'esbuild';

// packages/zk/src/sdk.ts loads the SDK with `createRequire`, which a bundler cannot follow. In the bundle the same
// CommonJS entry is reached through a plain `require`, which esbuild inlines (the SDK is CommonJS; see sdk.ts).
const inlineSdk: Plugin = {
  name: 'inline-zkpassport-sdk',
  setup(b) {
    b.onLoad({ filter: /packages\/zk\/src\/sdk\.ts$/ }, (args) => ({
      contents:
        "const sdk = require('@zkpassport/sdk');\nexport const ZKPassport = sdk.ZKPassport;\nexport const NullifierType = sdk.NullifierType;\n",
      loader: 'js',
      resolveDir: args.path.slice(0, args.path.lastIndexOf('/')),
    }));
  },
};

export async function bundleCli(outfile: string): Promise<void> {
  await build({
    entryPoints: [new URL('../src/bin.ts', import.meta.url).pathname],
    outfile,
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node24',
    legalComments: 'none',
    // The xrpl library's network client (`ws`) is replaced by a stub: nothing here may open a connection.
    alias: { ws: new URL('./offline-ws.js', import.meta.url).pathname },
    banner: {
      js: "import { createRequire as __legxRequire } from 'node:module'; const require = __legxRequire(import.meta.url);",
    },
    // zk proofs are verified by barretenberg, a native `bb` binary that cannot live inside a JS file: see release.ts
    define: { 'process.env.LEGX_BUNDLED': '"1"' },
    plugins: [inlineSdk],
    logLevel: 'warning',
  });
}

if (process.argv[1] === new URL(import.meta.url).pathname) await bundleCli(process.argv[2] ?? 'dist/verify.js');
