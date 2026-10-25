import { createFileRoute } from '@tanstack/react-router';
import { Wired } from './-screens/context.tsx';
import { RecoveryScreen } from './-screens/recovery.tsx';

export const Route = createFileRoute('/party/frost/recovery')({
  component: () => <Wired screen="recovery" render={(p) => <RecoveryScreen {...p} />} />,
});
