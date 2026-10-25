import { createFileRoute } from '@tanstack/react-router';
import { Wired } from './-screens/context.tsx';
import { RecoveryNotice } from './-screens/recovery.tsx';

export const Route = createFileRoute('/party/frost/recovery-notice')({
  component: () => <Wired screen="recoveryNotice" render={(p) => <RecoveryNotice {...p} />} />,
});
