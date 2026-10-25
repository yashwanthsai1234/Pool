// Must stay the first import: it turns off zod's `new Function` probe, which the Trusted Types CSP reports (see the dashboard).
import '../dashboard/-jitless.ts';
import { EmptyState, StatusBadge } from '@legx/ui';
import { lazy, Suspense, useState } from 'react';
import { useParty } from './-context.tsx';
import { BadgeScreen, HomeScreen, LockScreen, type Screen } from './-home.tsx';

// The screens that decode transactions or check signatures load on demand: their crypto is not part of the first download.
const ApproveScreen = lazy(() => import('./-approve.tsx').then((m) => ({ default: m.ApproveScreen })));
const PresenceScreen = lazy(() => import('./-presence.tsx').then((m) => ({ default: m.PresenceScreen })));
const RecordsScreen = lazy(() => import('./-records.tsx').then((m) => ({ default: m.RecordsScreen })));

const ROLES = { alice: 'Alice', bob: 'Bob' } as const;

/** `makeKey` opens the FROST key screens of task 4.7 (`/party/frost/dkg`). */
export function PartyApp({ role, makeKey }: { role: string; makeKey: () => void }) {
  const name = Object.hasOwn(ROLES, role) ? ROLES[role as keyof typeof ROLES] : undefined;
  const services = useParty();
  const [screen, setScreen] = useState<Screen>('home');
  if (!name)
    return (
      <main className="min-h-dvh bg-bg text-fg">
        <EmptyState title="Unknown role">
          <StatusBadge status="fail" /> Open the link your lawyer sent you.
        </EmptyState>
      </main>
    );
  if (!services || services.role !== role)
    return (
      <main className="min-h-dvh bg-bg text-fg">
        <EmptyState title={`Hello ${name}, no deal yet`}>
          When your lawyer opens a deal for you, it appears here and you will be asked to approve each step.
        </EmptyState>
      </main>
    );
  return (
    <main className="min-h-dvh bg-bg text-fg">
      {screen !== 'home' ? (
        <button type="button" className="m-4 underline" onClick={() => setScreen('home')}>
          Back to my deal
        </button>
      ) : null}
      {screen === 'home' ? <HomeScreen open={setScreen} makeKey={makeKey} /> : null}
      {screen === 'lock' ? <LockScreen /> : null}
      {screen === 'badge' ? <BadgeScreen /> : null}
      <Suspense fallback={<p className="p-4">Loading</p>}>
        {screen === 'presence' ? <PresenceScreen /> : null}
        {screen === 'approve' ? <ApproveScreen /> : null}
        {screen === 'records' ? <RecordsScreen /> : null}
      </Suspense>
    </main>
  );
}
