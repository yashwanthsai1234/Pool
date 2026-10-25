import { createFileRoute, useNavigate } from '@tanstack/react-router';
import { lazy, Suspense } from 'react';
import { PartyApp } from './-app.tsx';

// The vault frame client, the signed API client and the hybrid registry check are only needed when a deal link is
// open: they stay out of the first download (phone budget, apps/web/scripts/check-budget.ts).
const PartyHost = lazy(() => import('./-host.tsx').then((m) => ({ default: m.PartyHost })));

export const Route = createFileRoute('/party/$role')({ component: PartyRoute });

function PartyRoute() {
  const navigate = useNavigate();
  const { role } = Route.useParams();
  const app = <PartyApp role={role} makeKey={() => void navigate({ to: '/party/frost/dkg' })} />;
  if ((role !== 'alice' && role !== 'bob') || !new URLSearchParams(location.search).has('deal')) return app;
  return (
    <Suspense fallback={<p className="p-4">Loading</p>}>
      <PartyHost role={role} search={location.search} env={import.meta.env}>
        {app}
      </PartyHost>
    </Suspense>
  );
}
