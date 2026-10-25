// The golden examples of `@legx/contracts` are the mock data: one JSON file per schema, an array of valid examples.
// Source: https://vite.dev/guide/features#glob-import
const files = import.meta.glob<unknown[]>('../../../../packages/contracts/examples/*.json', {
  eager: true,
  import: 'default',
});

const byName = new Map(
  Object.entries(files).map(([path, examples]) => [path.slice(path.lastIndexOf('/') + 1, -'.json'.length), examples]),
);

/** All golden examples of a named schema, e.g. `route.deals.get.output`. Throws on an unknown name. */
export function examplesOf(name: string): readonly unknown[] {
  const examples = byName.get(name);
  if (!examples?.length) throw new Error(`no golden examples named ${name}`);
  return examples;
}
