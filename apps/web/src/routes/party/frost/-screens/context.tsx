// What the FROST screens need from the deal (task 4.3 wires it: the vault frame, the relay over the API client, the
// live feed). A route with nothing wired shows its empty state. The `-` prefix keeps this folder out of the route tree.
// Source: https://tanstack.com/router/latest/docs/framework/react/routing/file-naming-conventions (routeFileIgnorePrefix)
import { EmptyState } from '@legx/ui';
import { createContext, type ReactNode, useContext } from 'react';
import type { PqBindingScreenProps } from '../../-pq-binding.tsx';
import type { DkgScreenProps } from './dkg.tsx';
import type { RecoveryNoticeProps, RecoveryScreenProps } from './recovery.tsx';
import type { RefreshScreenProps } from './refresh.tsx';
import type { RotationScreenProps } from './rotation.tsx';
import type { SignScreenProps } from './sign.tsx';

export type FrostScreens = {
  dkg?: DkgScreenProps;
  sign?: SignScreenProps;
  recovery?: RecoveryScreenProps;
  recoveryNotice?: RecoveryNoticeProps;
  refresh?: RefreshScreenProps;
  rotation?: RotationScreenProps;
  pqBinding?: PqBindingScreenProps;
};

const Ctx = createContext<FrostScreens>({});
const useFrostScreens = (): FrostScreens => useContext(Ctx);

/** The route body: the screen when its ceremony is wired, else an empty state. */
export function Wired<K extends keyof FrostScreens>(p: {
  screen: K;
  render: (props: NonNullable<FrostScreens[K]>) => ReactNode;
}) {
  const props = useFrostScreens()[p.screen];
  return (
    <main className="min-h-dvh bg-bg text-fg">
      {props ? (
        p.render(props as NonNullable<FrostScreens[K]>)
      ) : (
        <EmptyState title="Nothing to do here yet">This step opens from your deal when it is needed.</EmptyState>
      )}
    </main>
  );
}
