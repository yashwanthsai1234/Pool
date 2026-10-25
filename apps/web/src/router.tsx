import type { QueryClient } from '@tanstack/react-query';
import { createMemoryHistory, createRouter } from '@tanstack/react-router';
import type { RouterContext } from './lib/router-context.ts';
import { routeTree } from './routeTree.gen.ts';

export function createAppRouter(queryClient: QueryClient, initialPath?: string) {
  return createRouter({
    routeTree,
    context: { queryClient },
    defaultPreload: 'intent',
    history: initialPath ? createMemoryHistory({ initialEntries: [initialPath] }) : undefined,
  });
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
