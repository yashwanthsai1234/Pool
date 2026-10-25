// One serialized pump per socket: wake-ups that arrive while the pump runs are coalesced into one more run.
// Replay and live use this one code path, so a row is sent exactly once and in order.

/** Returns a function that runs `fn` one call at a time; calls made during a run cause exactly one more run after it. */
export function serial(fn: () => Promise<void>): () => Promise<void> {
  let running: Promise<void> | undefined;
  let again = false;
  return () => {
    if (running) {
      again = true;
      return running;
    }
    running = (async () => {
      try {
        do {
          again = false;
          await fn();
        } while (again);
      } finally {
        running = undefined;
      }
    })();
    return running;
  };
}
