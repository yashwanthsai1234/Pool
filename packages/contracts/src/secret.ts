// Secret<> marks a field that must never be logged, traced, stored in an event, or returned by the API
// (IMPLEMENTATION 1.2 "Think hard", 4.3 pino `redact`). The brand is type-level; the JSON Schema
// keyword `x-legx-secret` makes the same mark visible at run time and in the committed schema snapshots.
import { z } from 'zod';

export const SECRET_KEYWORD = 'x-legx-secret';

/** A value that must never be logged or leave the component that owns it. */
export type Secret<T> = T & z.$brand<'Secret'>;

/**
 * Marks a schema as secret: brands its output type and tags its JSON Schema with `x-legx-secret`.
 * Source: https://zod.dev/api?id=branded-types and https://zod.dev/json-schema (metadata)
 */
export function secret<S extends z.ZodType>(schema: S) {
  return schema.brand<'Secret'>().meta({ [SECRET_KEYWORD]: true });
}

/**
 * JSON pointer paths (`/a/b/*`) of every secret field in a schema, for pino `redact` lists and review tests.
 * Array items appear as `*`, union branches share the parent path.
 */
export function secretPaths(schema: z.ZodType): string[] {
  const out = new Set<string>();
  const walk = (node: unknown, path: string): void => {
    if (node === null || typeof node !== 'object') return;
    const n = node as Record<string, unknown>;
    if (n[SECRET_KEYWORD] === true) out.add(path || '/');
    const props = n.properties as Record<string, unknown> | undefined;
    for (const [k, v] of Object.entries(props ?? {})) walk(v, `${path}/${k}`);
    for (const key of ['items', 'additionalProperties']) walk(n[key], `${path}/*`);
    for (const key of ['prefixItems', 'anyOf', 'oneOf', 'allOf']) {
      const list = n[key];
      if (Array.isArray(list)) for (const v of list) walk(v, key === 'prefixItems' ? `${path}/*` : path);
    }
  };
  walk(z.toJSONSchema(schema), '');
  return [...out].sort();
}
