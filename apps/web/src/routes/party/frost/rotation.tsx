import { createFileRoute } from '@tanstack/react-router';
import { Wired } from './-screens/context.tsx';
import { RotationScreen } from './-screens/rotation.tsx';

export const Route = createFileRoute('/party/frost/rotation')({
  component: () => <Wired screen="rotation" render={(p) => <RotationScreen {...p} />} />,
});
