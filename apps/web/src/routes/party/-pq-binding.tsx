// The post-quantum binding screen (DESIGN 6.13, IMPLEMENTATION 4.9 UI): the device shows the values it computed itself
// (deal seal, slot key, `pqKeyHash` from its own pinned keys), signs with its vault ML-DSA-65 key, waits for a second
// holder, cross-signs with the slot key and submits only a binding that core `verifyPqBinding` accepted.
// Source: DESIGN.md 6.13; https://csrc.nist.gov/pubs/fips/204/final (ML-DSA contexts)
import type { PqBinding } from '@legx/contracts/records';
import type { Slot } from '@legx/contracts/values';
import type { SignRequest } from '@legx/core/frostRules';
import { Button, StatusBadge } from '@legx/ui';
import type { PqHalf } from '@legx/vault';
import type { BindingProgress, BindingSessionInput, pqBindingSession } from '@legx/vault/pq/binding';
import { PQ_BINDING_TEXT } from '@legx/vault/pq/text';
import { useState } from 'react';
import type { z } from 'zod';

type Session = ReturnType<typeof pqBindingSession>;

export type PqBindingScreenProps = {
  slot: Slot;
  /** Builds the session from the device's own verified seal and pinned keys; throws `PqBindingError`. */
  open: (onProgress: BindingSessionInput['onProgress']) => Session;
  /** This device's ML-DSA-65 half (the vault's). */
  half: PqHalf;
  /** Resolves when a second holder's signature has been added to the session (over the relay). */
  peer: (session: Session) => Promise<void>;
  crossSign: (req: SignRequest) => Promise<Uint8Array>;
  submit: (binding: z.infer<typeof PqBinding>) => Promise<void>;
};

/** `PqBindingError` carries a `code`; it is read by shape so the screen does not import the crypto. */
const codeOf = (e: unknown): string | undefined =>
  e instanceof Error && e.name === 'PqBindingError' ? (e as { code?: string }).code : undefined;

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

const FAILED: Record<string, string> = {
  KEY_MISMATCH: PQ_BINDING_TEXT.keyMismatch,
  SEAL_MISMATCH: PQ_BINDING_TEXT.sealMismatch,
};

export function PqBindingScreen(p: PqBindingScreenProps) {
  const [step, setStep] = useState<BindingProgress | 'waiting'>();
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string>();
  const [opened] = useState(() => {
    try {
      const session = p.open((s) => setStep(s));
      return { session } as const;
    } catch (e) {
      return { failure: FAILED[codeOf(e) ?? ''] ?? codeOf(e) ?? 'Could not open the binding' };
    }
  });
  const session = 'session' in opened ? opened.session : undefined;

  const run = async () => {
    if (!session) return;
    setError(undefined);
    try {
      await session.signWith(p.half);
      setStep('waiting');
      if (session.status() !== 'ready') await p.peer(session);
      await session.finish(p.crossSign, p.submit);
      setDone(true);
    } catch (e) {
      setError(`Not recorded: ${codeOf(e) ?? 'the coordinator or a signature failed'}`);
    }
  };

  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="pq-title">
      <h1 id="pq-title" className="text-2xl font-bold">
        Post-quantum binding
      </h1>
      <p role="note">{PQ_BINDING_TEXT.help}</p>
      {'failure' in opened ? <p role="alert">{opened.failure}</p> : null}
      {session ? (
        <dl className="flex flex-col gap-1 break-all">
          <dt>Deal seal</dt>
          <dd data-testid="pq-deal-seal">{hex(session.fields.dealSeal)}</dd>
          <dt>Slot key</dt>
          <dd data-testid="pq-slot-key">{hex(session.fields.slotPub).toUpperCase()}</dd>
          <dt>Post-quantum key set</dt>
          <dd data-testid="pq-key-hash">{hex(session.fields.pqKeyHash)}</dd>
        </dl>
      ) : null}
      {session && !done ? (
        <Button onClick={run} disabled={step !== undefined && !error}>
          Sign the binding
        </Button>
      ) : null}
      {step === 'waiting' && !done && !error ? <p role="status">{PQ_BINDING_TEXT.waiting}</p> : null}
      {step && step !== 'waiting' && !done && !error ? <p role="status">{PQ_BINDING_TEXT.progress[step]}</p> : null}
      {error ? <p role="alert">{error}</p> : null}
      {done ? (
        <p role="status">
          <StatusBadge status="pass" /> Post-quantum binding recorded
        </p>
      ) : null}
    </section>
  );
}
