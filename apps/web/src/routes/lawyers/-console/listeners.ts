// The subscribe/notify half of an external store, as `useSyncExternalStore` wants it (`subscribe` returns the unsubscribe).
// Source: https://react.dev/reference/react/useSyncExternalStore
export function createListeners() {
  const set = new Set<() => void>();
  return {
    notify: () => {
      for (const l of set) l();
    },
    subscribe: (fn: () => void) => {
      set.add(fn);
      return () => void set.delete(fn);
    },
  };
}
