// Fuzz targets for the contract schemas: every API request schema, the WebSocket messages, the DSSE and hybrid envelopes,
// the FROST wire messages, and the records and events. A random input must give a result and never throw, and an accepted
// input must round-trip through JSON to the same value.
// Source: https://zod.dev/api (safeParse never throws on bad input), IMPLEMENTATION 5.2
import { listRoutes, SCHEMAS } from '@legx/contracts/catalog';
import type { z } from 'zod';
import { assert, assertEqual, attempt, jsonOf, type Target, toBytes } from '../src/harness.ts';
import { contractExamples } from '../src/seeds.ts';

/** Applies each schema to the input. Accepted: parse(JSON(parsed)) must give the same value (and stay accepted). */
export function checkSchemas(schemas: Readonly<Record<string, z.ZodType>>, input: Uint8Array): number {
  const doc = jsonOf(input);
  let accepted = 0;
  for (const [name, schema] of Object.entries(schemas)) {
    const first = attempt(name, () => schema.safeParse(doc));
    if (!first.ok || !first.value.success) continue;
    accepted++;
    const again = attempt(name, () => schema.safeParse(JSON.parse(JSON.stringify(first.value.data))));
    assert(again.ok && again.value.success, `${name}: an accepted value is rejected after a JSON round trip`);
    if (again.ok && again.value.success)
      assertEqual(
        JSON.parse(JSON.stringify(first.value.data)),
        JSON.parse(JSON.stringify(again.value.data)),
        `${name}: round trip`,
      );
  }
  return accepted;
}

function schemaTarget(
  name: string,
  schemas: Readonly<Record<string, z.ZodType>>,
  seedNames: (examples: Map<string, Uint8Array[]>) => Uint8Array[],
): Target {
  return {
    name,
    pkg: 'contracts',
    seeds: () => seedNames(contractExamples()),
    run(input) {
      checkSchemas(schemas, input);
    },
  };
}

const only = (...names: string[]): Record<string, z.ZodType> =>
  Object.fromEntries(names.map((n) => [n, SCHEMAS[n] as z.ZodType]));
const examplesOf = (names: readonly string[]) => (ex: Map<string, Uint8Array[]>) =>
  names.flatMap((n) => ex.get(n) ?? []);

const ROUTE_INPUTS = Object.fromEntries(
  listRoutes().map((r) => [`route.${r.name}.input`, SCHEMAS[`route.${r.name}.input`] as z.ZodType]),
);
const TAKEN = new Set([
  ...Object.keys(ROUTE_INPUTS),
  ...Object.keys(SCHEMAS).filter((n) => n.startsWith('route.')),
  'WsClientMessage',
  'WsServerMessage',
  'Envelope',
  'HybridEnvelope',
  'FrostMessage',
  'FrostSignedMessage',
  'ZkVerification',
  'ZkVerifyRequest',
]);
const RECORDS = Object.fromEntries(Object.entries(SCHEMAS).filter(([n]) => !TAKEN.has(n)));

export const schemaTargets: Target[] = [
  schemaTarget('api-requests', ROUTE_INPUTS, (ex) =>
    [...ex].filter(([n]) => /^route\..*\.input$/.test(n)).flatMap(([, b]) => b),
  ),
  schemaTarget(
    'ws-messages',
    only('WsClientMessage', 'WsServerMessage'),
    examplesOf(['WsClientMessage', 'WsServerMessage']),
  ),
  schemaTarget('dsse-schemas', only('Envelope', 'HybridEnvelope'), examplesOf(['Envelope', 'HybridEnvelope'])),
  schemaTarget(
    'frost-schemas',
    only('FrostMessage', 'FrostSignedMessage'),
    examplesOf(['FrostMessage', 'FrostSignedMessage']),
  ),
  schemaTarget('records-events', RECORDS, (ex) =>
    [...ex].filter(([n]) => !n.startsWith('route.') && !TAKEN.has(n)).flatMap(([, b]) => b),
  ),
];

export { toBytes };
