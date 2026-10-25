import { createFileRoute } from '@tanstack/react-router';
import { Wired } from './-screens/context.tsx';
import { SignScreen } from './-screens/sign.tsx';

export const Route = createFileRoute('/party/frost/sign')({
  component: () => <Wired screen="sign" render={(p) => <SignScreen {...p} />} />,
});
