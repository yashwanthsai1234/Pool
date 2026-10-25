// Loading and offline states shared by the screens. A failed query never looks like an empty deal, and nothing is signed
// while the coordinator cannot be reached.
import { Button } from '@legx/ui';
import type { UseQueryResult } from '@tanstack/react-query';
import type { ReactNode } from 'react';

/** The element to show while any query is loading or failed, or undefined when all have data. */
export function gate(...queries: UseQueryResult<unknown>[]): ReactNode | undefined {
  const failed = queries.find((q) => q.isError);
  if (failed)
    return (
      <div role="alert" className="mx-auto flex max-w-md flex-col gap-3 p-4">
        <p className="font-bold">Cannot reach the coordinator. Nothing was signed.</p>
        <Button
          onClick={() => {
            for (const q of queries) if (q.isError) void q.refetch();
          }}
        >
          Try again
        </Button>
      </div>
    );
  if (queries.some((q) => q.isPending)) return <p className="p-4">Loading</p>;
  return undefined;
}
