import { createFileRoute } from '@tanstack/react-router';
import { Wired } from './-screens/context.tsx';
import { RefreshScreen } from './-screens/refresh.tsx';

export const Route = createFileRoute('/party/frost/refresh')({
  component: () => <Wired screen="refresh" render={(p) => <RefreshScreen {...p} />} />,
});
