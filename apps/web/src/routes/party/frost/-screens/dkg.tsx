// The DKG ceremony screen (P4.7-01, 02, 13, 14, 15, 19): key pinning (the QR code between the client's two devices),
// the rounds with the transcript echo, a refused key or a complaint named on screen, the three test-signing pairs,
// and the slot key's fingerprint once all three pairs are green. Used by the party and the lawyer routes.

import { Button, StatusBadge } from '@legx/ui';
import type { DkgEvent } from '@legx/vault/frost/dkg';
import { SINGLE_DEVICE_LABEL } from '@legx/vault/rules';
import { useState } from 'react';

export type DkgScreenProps = {
  slot: 'A' | 'B' | 'LA' | 'LB';
  /** The three holders as pinned, in role order. */
  holders: { label: string; fingerprint: string }[];
  /** Share 2 is a passkey on this same phone: labeled on every summary (P4.7-19). */
  singleDevice?: boolean;
  /** The client's two devices pin each other first: this device's code, and the check of the other device's code. */
  pin?: { code: string; sas: string; check: (scanned: string, sas: string) => void };
  run: (onEvent: (e: DkgEvent) => void) => Promise<unknown>;
};

const STEPS = [
  ['round1', 'Round 1: commitments sent'],
  ['echo', 'Transcript check: every holder saw the same round 1'],
  ['round2', 'Round 2: sealed shares sent'],
] as const;

export function DkgScreen(p: DkgScreenProps) {
  const [events, setEvents] = useState<DkgEvent[]>([]);
  const [running, setRunning] = useState(false);
  const [pinned, setPinned] = useState(!p.pin);
  const [pinError, setPinError] = useState<string>();
  const [scanned, setScanned] = useState('');
  const [sas, setSas] = useState('');
  const of = <K extends DkgEvent['kind']>(k: K) =>
    events.filter((e) => e.kind === k) as Extract<DkgEvent, { kind: K }>[];
  const steps = new Set(of('step').map((e) => e.step));
  const refused = of('refused')[0];
  const aborted = of('aborted')[0];
  const pairs = of('pair').map((e) => e.result);
  const ready = of('ready')[0];
  const failedPair = pairs.some((x) => !x.ok);

  const start = async () => {
    setRunning(true);
    await p.run((e) => setEvents((xs) => [...xs, e])).catch(() => undefined); // the events say what happened
    setRunning(false);
  };
  const pin = () => {
    try {
      p.pin?.check(scanned, sas);
      setPinned(true);
      setPinError(undefined);
    } catch (e) {
      setPinError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="dkg-title">
      <h1 id="dkg-title" className="text-2xl font-bold">
        Set up the signing key for slot {p.slot}
      </h1>
      {p.singleDevice ? (
        <p role="note" className="rounded-md border-2 border-fail p-3 font-semibold">
          {SINGLE_DEVICE_LABEL}
        </p>
      ) : null}
      <h2 className="text-lg font-semibold">Key holders</h2>
      <ul className="flex flex-col gap-1">
        {p.holders.map((h) => (
          <li key={h.fingerprint}>
            {h.label} <span className="font-mono text-muted">{h.fingerprint}</span>
          </li>
        ))}
      </ul>

      {p.pin ? (
        <fieldset className="flex flex-col gap-2 rounded-md border-2 border-line p-3">
          <legend className="font-semibold">Pin your other device</legend>
          <p>Show this code to your other device (as a QR code):</p>
          <output aria-label="Pairing code" className="block break-all font-mono text-sm">
            {p.pin.code}
          </output>
          <p>
            Both screens must show <strong>{p.pin.sas}</strong>.
          </p>
          <label htmlFor="pin-scanned">Code scanned from your other device</label>
          <textarea
            id="pin-scanned"
            className="border-2 border-line"
            value={scanned}
            onChange={(e) => setScanned(e.target.value)}
          />
          <label htmlFor="pin-sas">Six digits shown on your other device</label>
          <input
            id="pin-sas"
            className="border-2 border-line"
            inputMode="numeric"
            value={sas}
            onChange={(e) => setSas(e.target.value)}
          />
          <Button variant="outline" onClick={pin} disabled={pinned}>
            {pinned ? 'Pinned' : 'Pin this device'}
          </Button>
          {pinError ? <p role="alert">{pinError}</p> : null}
        </fieldset>
      ) : null}

      <Button onClick={start} disabled={!pinned || running || events.length > 0}>
        Start key setup
      </Button>

      {refused ? (
        <p role="alert">
          Refused key: {refused.label} ({refused.fingerprint}). Nothing was sent.
        </p>
      ) : null}

      {events.length > 0 && !refused ? (
        <ol className="flex flex-col gap-1" aria-label="Key setup steps">
          {STEPS.map(([k, label]) => (
            <li key={k}>
              <StatusBadge status={steps.has(k) ? 'pass' : aborted ? 'fail' : 'pending'} /> {label}
            </li>
          ))}
        </ol>
      ) : null}

      {aborted ? (
        <div role="alert" className="flex flex-col gap-1">
          <p className="font-semibold">Key setup stopped. No share was stored.</p>
          {aborted.culprit ? <p>Cause: {aborted.culprit}.</p> : null}
          {aborted.complaint ? <p>A signed complaint was sent to every holder.</p> : null}
          <p className="text-muted">{aborted.reason}</p>
        </div>
      ) : null}

      {pairs.length > 0 ? (
        <>
          <h2 className="text-lg font-semibold">Test signatures</h2>
          <ul className="flex flex-col gap-1" aria-label="Test signatures">
            {pairs.map((x) => (
              <li key={x.names.join('+')}>
                <StatusBadge status={x.ok ? 'pass' : 'fail'} /> {x.names.join(' + ')}
              </li>
            ))}
          </ul>
        </>
      ) : null}

      {ready ? (
        <p role="status">
          Slot key ready. Fingerprint: <span className="font-mono">{ready.fingerprint}</span>
          {p.singleDevice ? ` (${SINGLE_DEVICE_LABEL})` : ''}
        </p>
      ) : failedPair && !running ? (
        <p role="alert">Slot key not ready: a test signature failed. No share was stored.</p>
      ) : null}
    </section>
  );
}
