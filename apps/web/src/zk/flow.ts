// The request lifecycle as a reducer (one screen text per state) and a hook that wires an SDK request to it.
// A result is accepted only after the phone started proving; nothing is signed here, the lawyer's console checks.
// Source: IMPLEMENTATION 4.8 (P4.8-03, -11)
import { useCallback, useEffect, useReducer, useRef } from 'react';
import { ZkWebError } from './policy.ts';
import type { ZkRequest } from './request.ts';
import type { ZkOutcome } from './sdk.ts';

export type ZkState =
  | { readonly step: 'idle' }
  | { readonly step: 'waiting'; readonly url: string }
  | { readonly step: 'received'; readonly url: string }
  | { readonly step: 'proving'; readonly url: string }
  | { readonly step: 'proof-ready'; readonly url: string }
  | { readonly step: 'done'; readonly outcome: ZkOutcome }
  | { readonly step: 'rejected' }
  | { readonly step: 'timeout' }
  | { readonly step: 'error'; readonly message: string };

export type ZkEvent =
  | { readonly type: 'start'; readonly url: string }
  | { readonly type: 'received' | 'generating' | 'generated' | 'reject' | 'timeout' | 'reset' }
  | { readonly type: 'result'; readonly outcome: ZkOutcome }
  | { readonly type: 'error'; readonly message: string };

const urlOf = (s: ZkState) => ('url' in s ? s.url : undefined);

/** Events out of order are ignored (a result with no request, a second result after done); an error always shows. */
export function zkReducer(s: ZkState, e: ZkEvent): ZkState {
  const url = urlOf(s);
  switch (e.type) {
    case 'start':
      return { step: 'waiting', url: e.url };
    case 'reset':
      return { step: 'idle' };
    case 'error':
      return s.step === 'done' ? s : { step: 'error', message: e.message };
    case 'received':
      return s.step === 'waiting' && url ? { step: 'received', url } : s;
    case 'generating':
      return (s.step === 'waiting' || s.step === 'received') && url ? { step: 'proving', url } : s;
    case 'generated':
      return s.step === 'proving' && url ? { step: 'proof-ready', url } : s;
    case 'result':
      return s.step === 'proving' || s.step === 'proof-ready' ? { step: 'done', outcome: e.outcome } : s;
    case 'reject':
      return url && s.step !== 'done' ? { step: 'rejected' } : s;
    case 'timeout':
      return url && s.step !== 'done' ? { step: 'timeout' } : s;
  }
}

const ZK_TEXT: Record<ZkState['step'], string> = {
  idle: 'Ready to start.',
  waiting: 'Scan the code with the ZKPassport app, or open the link on your phone.',
  received: 'Request received on your phone. Follow the steps in the app.',
  proving: 'Your phone is making the proof. This can take up to a minute.',
  'proof-ready': 'Proof made on your phone. Waiting for the result.',
  done: 'Passport proof done.',
  rejected: 'You declined the request in the app.',
  timeout: 'The phone app did not answer in time.',
  error: 'Something went wrong with the passport request.',
};

/** Fifty-second proofs are normal; the screen waits this long for the next phone event before it gives up. */
const ZK_TIMEOUT_MS = 120_000;

export function useZkFlow(timeoutMs = ZK_TIMEOUT_MS) {
  const [state, dispatch] = useReducer(zkReducer, { step: 'idle' });
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const arm = useCallback(() => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => dispatch({ type: 'timeout' }), timeoutMs);
  }, [timeoutMs]);
  useEffect(() => () => clearTimeout(timer.current), []);

  /** Starts from a request builder; a refusal before the SDK (stale anchor, long bound value) is an error state. */
  const start = useCallback(
    async (build: () => Promise<ZkRequest>) => {
      dispatch({ type: 'reset' });
      try {
        const r = await build();
        dispatch({ type: 'start', url: r.url });
        arm();
        const step = (type: 'received' | 'generating' | 'generated' | 'reject') => () => {
          dispatch({ type });
          arm();
        };
        r.onRequestReceived(step('received'));
        r.onGeneratingProof(step('generating'));
        r.onProofGenerated(step('generated'));
        r.onReject(() => {
          clearTimeout(timer.current);
          dispatch({ type: 'reject' });
        });
        r.onResult((outcome) => {
          clearTimeout(timer.current);
          dispatch({ type: 'result', outcome });
        });
        r.onError((message) => {
          clearTimeout(timer.current);
          dispatch({ type: 'error', message });
        });
      } catch (e) {
        dispatch({ type: 'error', message: e instanceof ZkWebError ? e.code : 'REQUEST_FAILED' });
      }
    },
    [arm],
  );
  return { state, start, text: ZK_TEXT[state.step] };
}
