// Two-share signing (P4.7-03, 05, 07, 21): the phone (or console) asks for the second share holder first (a tap of the
// security key, an approval on the second device, or the lawyer's approval for the firm HSM), then signs. The screen
// says which holders took part, so the user sees that the recovery agent was not needed for a normal signature.

import { Button, StatusBadge } from '@legx/ui';
import { SINGLE_DEVICE_LABEL } from '@legx/vault/rules';
import { useState } from 'react';

export type SignScreenProps = {
  /** What is being signed, in words (decoded by task 4.3 from the exact bytes). */
  summary: string;
  /** Who holds share 2, in words: "your security key", "your second device", "your firm's HSM". */
  second: 'security-key' | 'second-device' | 'firm-hsm' | 'single-device';
  holders: [string, string];
  sign: () => Promise<unknown>;
  /** The refusal reason a remote holder gave (the vault itself only says APPROVAL_REFUSED). */
  refusal?: () => string | undefined;
};

const ASK: Record<SignScreenProps['second'], string> = {
  'security-key': 'Tap your security key.',
  'single-device': 'Confirm with this phone’s passkey.',
  'second-device': 'Approve on your second device.',
  'firm-hsm': 'Approve with your security key: your firm’s HSM signs only what you approve.',
};

const errorText = (code: string, second: SignScreenProps['second'], reason?: string): string => {
  if (code === 'PASSKEY_REQUIRED') return 'The security key was not used. Nothing was signed.';
  if (code === 'APPROVAL_REFUSED' && second === 'firm-hsm')
    return reason && reason !== 'APPROVAL_MISSING'
      ? `Your firm's HSM refused: ${reason}. Nothing was signed.`
      : "Your firm's HSM needs your approval. Nothing was signed.";
  if (code === 'APPROVAL_REFUSED') return 'Your second device did not approve. Nothing was signed.';
  if (code === 'MESSAGE_REFUSED') return 'This request is not one the deal allows. Nothing was signed.';
  return `Signing failed (${code}). A new signing session starts when you try again.`;
};

export function SignScreen(p: SignScreenProps) {
  const [state, setState] = useState<'idle' | 'asking' | 'signed' | 'failed'>('idle');
  const [error, setError] = useState('');
  const approve = async () => {
    setState('asking');
    try {
      await p.sign(); // every attempt is a new session with new nonces (P4.7-07)
      setState('signed');
    } catch (e) {
      setError(errorText((e as { code?: string }).code ?? (e as Error).message, p.second, p.refusal?.()));
      setState('failed');
    }
  };
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="sign-title">
      <h1 id="sign-title" className="text-2xl font-bold">
        Approve
      </h1>
      <p>{p.summary}</p>
      {p.second === 'single-device' ? <p role="note">{SINGLE_DEVICE_LABEL}</p> : null}
      <Button onClick={approve} disabled={state === 'asking' || state === 'signed'}>
        {state === 'failed' ? 'Try again' : 'Approve payment'}
      </Button>
      {state === 'asking' ? <p role="status">{ASK[p.second]}</p> : null}
      {state === 'signed' ? (
        <p role="status">
          <StatusBadge status="pass" /> Signed by {p.holders[0]} and {p.holders[1]}. The recovery agent was not needed.
        </p>
      ) : null}
      {state === 'failed' ? (
        <p role="alert">
          <StatusBadge status="fail" /> {error}
        </p>
      ) : null}
    </section>
  );
}
