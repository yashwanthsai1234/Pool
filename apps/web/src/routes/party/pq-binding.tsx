import { createFileRoute } from '@tanstack/react-router';
import { PqBindingScreen } from './-pq-binding.tsx';
import { Wired } from './frost/-screens/context.tsx';

export const Route = createFileRoute('/party/pq-binding')({
  component: () => <Wired screen="pqBinding" render={(p) => <PqBindingScreen {...p} />} />,
});
