import { createFileRoute } from '@tanstack/react-router';
import { Wired } from '../../party/frost/-screens/context.tsx';
import { SignScreen } from '../../party/frost/-screens/sign.tsx';

export const Route = createFileRoute('/lawyers/frost/sign')({
  component: () => <Wired screen="sign" render={(p) => <SignScreen {...p} />} />,
});
