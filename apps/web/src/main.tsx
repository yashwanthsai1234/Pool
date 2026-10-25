// Must stay the first import: zod's JIT probe is a `new Function`, which the Trusted Types CSP reports, and any chunk that builds a zod
// schema at load (the vault frame client, the contracts) would otherwise run it before a route's own import of this file.
import './routes/dashboard/-jitless.ts';
import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import { createQueryClient } from './lib/query.ts';
import { registerServiceWorker } from './lib/sw.ts';
import { createAppRouter } from './router.tsx';

const queryClient = createQueryClient();
const router = createAppRouter(queryClient);
const root = document.getElementById('root');
if (!root) throw new Error('missing #root');

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
registerServiceWorker();
