// The ZKPassport SDK, loaded through CommonJS: a plain ESM import of @zkpassport/sdk 0.19.2 fails under Node
// (ERR_UNSUPPORTED_DIR_IMPORT on 'buffer/'; research r6, prototype of 24 Oct 2026).
// Source: https://nodejs.org/api/module.html#modulecreaterequirefilename
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import type * as Sdk from '@zkpassport/sdk';

const require = createRequire(import.meta.url);

export const { ZKPassport, NullifierType } = require('@zkpassport/sdk') as typeof Sdk;
export type { ProofResult, Query, QueryBuilder, QueryResult } from '@zkpassport/sdk';

/** The pinned versions every recording names; the tests fail when the installed ones differ (a re-record step). */
export const PINNED = { sdk: '0.19.2', utils: '0.40.0-beta.2', registry: '0.15.3' } as const;

/** The installed versions, with utils and registry as the SDK itself resolves them. */
export function installedVersions(): { sdk: string; utils: string; registry: string } {
  const sdkRequire = createRequire(require.resolve('@zkpassport/sdk'));
  return {
    sdk: versionOf(require, '@zkpassport/sdk'),
    utils: versionOf(sdkRequire, '@zkpassport/utils'),
    registry: versionOf(sdkRequire, '@zkpassport/registry'),
  };
}

// The packages do not export package.json, so read it next to the resolved entry point.
function versionOf(req: NodeJS.Require, name: string): string {
  const entry = req.resolve(name);
  const root = entry.slice(0, entry.lastIndexOf(`/${name}/`) + name.length + 1);
  return (JSON.parse(readFileSync(`${root}/package.json`, 'utf8')) as { version: string }).version;
}
