import { createRootRouteWithContext, Outlet } from '@tanstack/react-router';
import type { RouterContext } from '../lib/router-context.ts';
import { SecureContextGate } from '../lib/secure-context.tsx';

export const Route = createRootRouteWithContext<RouterContext>()({
  component: () => (
    <SecureContextGate>
      <Outlet />
    </SecureContextGate>
  ),
});
