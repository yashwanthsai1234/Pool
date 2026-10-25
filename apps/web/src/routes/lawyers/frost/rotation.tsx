import { createFileRoute } from '@tanstack/react-router';
import { Wired } from '../../party/frost/-screens/context.tsx';
import { RotationScreen } from '../../party/frost/-screens/rotation.tsx';

export const Route = createFileRoute('/lawyers/frost/rotation')({
  component: () => <Wired screen="rotation" render={(p) => <RotationScreen {...p} />} />,
});
