import { createFileRoute } from '@tanstack/react-router';
import { Wired } from '../../party/frost/-screens/context.tsx';
import { RecoveryNotice } from '../../party/frost/-screens/recovery.tsx';

export const Route = createFileRoute('/lawyers/frost/recoveries')({
  component: () => <Wired screen="recoveryNotice" render={(p) => <RecoveryNotice {...p} canCancel={false} />} />,
});
