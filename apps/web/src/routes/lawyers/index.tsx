import { EmptyState } from '@legx/ui';
import { createFileRoute } from '@tanstack/react-router';
import { lazy, Suspense } from 'react';
import { LawyerConsolePage, useConsoleWiring } from './-console/ui.tsx';

// The vault frame client and the signed API client stay out of the first download.
const LawyerConsoleHost = lazy(() => import('./-console-host.tsx').then((m) => ({ default: m.LawyerConsoleHost })));
const LawyerDealsHost = lazy(() => import('./-deals-host.tsx').then((m) => ({ default: m.LawyerDealsHost })));

const str = (v: unknown) => (typeof v === 'string' && v !== '' ? v : undefined);

function Lawyers() {
  const wiring = useConsoleWiring();
  if (wiring.LA || wiring.LB) return <LawyerConsolePage wiring={wiring} />;
  const [vaultOrigin, rpcUrl] = [str(import.meta.env.VITE_VAULT_ORIGIN), str(import.meta.env.VITE_LEGX_XRPL_RPC)];
  const params = new URLSearchParams(location.search);
  const dealId = str(params.get('deal'));
  return (
    <main className="min-h-dvh bg-bg text-fg">
      {vaultOrigin && rpcUrl && dealId ? (
        <Suspense fallback={<p className="p-4">Loading</p>}>
          <LawyerConsoleHost
            dealId={dealId}
            role={params.get('role') === 'LB' ? 'LB' : 'LA'}
            vaultOrigin={vaultOrigin}
            rpcUrl={rpcUrl}
          />
        </Suspense>
      ) : vaultOrigin && rpcUrl ? (
        <Suspense fallback={<p className="p-4">Loading</p>}>
          <LawyerDealsHost search={location.search} vaultOrigin={vaultOrigin} rpcUrl={rpcUrl} />
        </Suspense>
      ) : (
        <EmptyState title="No deals assigned">
          Deals your firm is a party to will be listed here, with the step that needs your signature.
        </EmptyState>
      )}
    </main>
  );
}

export const Route = createFileRoute('/lawyers/')({ component: Lawyers });
