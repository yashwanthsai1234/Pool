import { createFileRoute } from '@tanstack/react-router';
import { Wired } from './-screens/context.tsx';
import { DkgScreen } from './-screens/dkg.tsx';

export const Route = createFileRoute('/party/frost/dkg')({
  component: () => <Wired screen="dkg" render={(p) => <DkgScreen {...p} />} />,
});
