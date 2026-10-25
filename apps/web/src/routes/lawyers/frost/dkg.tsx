import { createFileRoute } from '@tanstack/react-router';
import { Wired } from '../../party/frost/-screens/context.tsx';
import { DkgScreen } from '../../party/frost/-screens/dkg.tsx';

export const Route = createFileRoute('/lawyers/frost/dkg')({
  component: () => <Wired screen="dkg" render={(p) => <DkgScreen {...p} />} />,
});
