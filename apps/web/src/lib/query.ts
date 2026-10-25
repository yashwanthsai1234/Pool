import { QueryClient } from '@tanstack/react-query';

// Server state lives in TanStack Query only. Live events update the cache, so data never goes stale by timer.
// Never put a key or secret into the cache.
export function createQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { staleTime: Number.POSITIVE_INFINITY, retry: false } } });
}
