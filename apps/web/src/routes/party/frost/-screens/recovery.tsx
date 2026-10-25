// Recovery on a new phone (P4.7-16, P4.7-19) and the notice on the old device and the lawyers' consoles (P4.7-17).
// The new phone: a fresh passport proof with a face match, then the 72-hour delay with a countdown by ledger time and
// who was told; the old device can cancel. Only after the delay does the "repair and refresh" button work, so no
// recovery share is used before it ends. Then the refresh screen's deletion statements.
import type { FrostRefreshed } from '@legx/core/frostRefresh';
import { Button, StatusBadge } from '@legx/ui';
import type { FreshProof, RecoveryApi } from '@legx/vault/frost/recovery';
import { HYGIENE_NOTE, NOTIFIED, type RecoveryStatus, remaining } from '@legx/vault/frost/text';
import { SINGLE_DEVICE_LABEL } from '@legx/vault/rules';
import { useEffect, useState } from 'react';

export type RecoveryScreenProps = {
  dealId: string;
  slot: 'A' | 'B';
  newKeyId: string;
  onboardingIdentifier: string;
  agentLabel: string;
  singleDevice?: boolean;
  api: RecoveryApi;
  /** Ledger time in ms (the latest validated ledger, OD-10). */
  ledgerNow: () => number;
  /** The ZKPassport flow (task 4.8): a fresh proof with a face match. */
  getProof: () => Promise<FreshProof>;
  /** Repair and refresh after the delay; resolves with the refresh record. */
  repairAndRefresh: () => Promise<FrostRefreshed>;
  pollMs?: number;
};

export function RecoveryScreen(p: RecoveryScreenProps) {
  const [refusal, setRefusal] = useState<string>();
  const [status, setStatus] = useState<RecoveryStatus>();
  const [now, setNow] = useState(p.ledgerNow());
  const [done, setDone] = useState<FrostRefreshed>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (status?.state !== 'waiting') return;
    const t = setInterval(async () => {
      setNow(p.ledgerNow());
      const s = await p.api.recovery.get({ dealId: p.dealId, recoveryId: status.recoveryId }).catch(() => undefined);
      if (s && s.state !== status.state) setStatus(s);
    }, p.pollMs ?? 30_000);
    return () => clearInterval(t);
  }, [status, p]);

  const start = async () => {
    setRefusal(undefined);
    const proof = await p.getProof();
    // the proof check pulls in the signing code, so it loads only now (the route chunk stays small, P4.1-06)
    const { proofRefusal } = await import('@legx/vault/frost/recovery');
    const reason = proofRefusal(proof, p.onboardingIdentifier, p.slot, p.ledgerNow());
    if (reason) return setRefusal(reason);
    try {
      setStatus(
        await p.api.recovery.start({
          kind: 'client',
          dealId: p.dealId,
          slot: p.slot,
          newKeyId: p.newKeyId,
          proof: proof.verification,
        }),
      );
    } catch (e) {
      setRefusal(`The recovery agent refused: ${(e as Error).message}`);
    }
  };
  const repair = async () => {
    try {
      setDone(await p.repairAndRefresh());
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const left = status ? remaining(status, now) : undefined;
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="rec-title">
      <h1 id="rec-title" className="text-2xl font-bold">
        Recover your signing share on this phone
      </h1>
      <p>
        The recovery agent ({p.agentLabel}) holds one share. It signs nothing on its own: it needs this request, a fresh
        passport proof with a face match, and a 72-hour wait that your old device can cancel.
      </p>
      {p.singleDevice ? (
        <p role="note">
          {SINGLE_DEVICE_LABEL}. Recovering in this mode means a thief with this phone needs nothing more.
        </p>
      ) : null}
      {!status ? <Button onClick={start}>Scan your passport</Button> : null}
      {refusal ? <p role="alert">{refusal}</p> : null}
      {status?.state === 'waiting' ? (
        <div role="status" className="flex flex-col gap-1">
          <p>
            Waiting period: <strong data-testid="countdown">{left?.text}</strong> left.
          </p>
          <p>We told {NOTIFIED.join(', ')}. Your old device can cancel until then.</p>
        </div>
      ) : null}
      {status?.state === 'cancelled' ? <p role="alert">This recovery was cancelled from your old device.</p> : null}
      {status ? (
        <Button onClick={repair} disabled={status.state !== 'ready' || !!done}>
          Repair and refresh
        </Button>
      ) : null}
      {error ? <p role="alert">{error}</p> : null}
      {done ? <RefreshResult record={done} /> : null}
    </section>
  );
}

function RefreshResult({ record }: { record: FrostRefreshed }) {
  return (
    <div role="status">
      <p>
        <StatusBadge status={record.status === 'COMPLETE' ? 'pass' : 'pending'} />{' '}
        {record.status === 'COMPLETE'
          ? 'Refresh complete'
          : `Waiting for ${record.missing.length} deletion statement(s)`}
      </p>
      <p className="text-muted">{HYGIENE_NOTE}</p>
    </div>
  );
}

export type RecoveryNoticeProps = {
  dealId: string;
  recoveryId: string;
  api: RecoveryApi;
  ledgerNow: () => number;
  /** The old device can cancel; a lawyer's console only sees the notice. */
  canCancel: boolean;
  pollMs?: number;
};

export function RecoveryNotice(p: RecoveryNoticeProps) {
  const [status, setStatus] = useState<RecoveryStatus>();
  useEffect(() => {
    let live = true;
    const load = () =>
      p.api.recovery
        .get({ dealId: p.dealId, recoveryId: p.recoveryId })
        .then((s) => live && setStatus(s))
        .catch(() => undefined);
    void load();
    const t = setInterval(load, p.pollMs ?? 30_000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [p]);
  if (!status) return null;
  const cancel = async () => setStatus(await p.api.recovery.cancel({ dealId: p.dealId, recoveryId: p.recoveryId }));
  return (
    <section className="mx-auto flex max-w-md flex-col gap-3 p-4" aria-labelledby="notice-title">
      <h1 id="notice-title" className="text-2xl font-bold">
        Recovery of slot {status.slot}
      </h1>
      {status.state === 'cancelled' ? (
        <p role="status">Recovery cancelled by the old device.</p>
      ) : (
        <p role="alert">
          Someone started recovering slot {status.slot} on a new phone. It can go ahead in{' '}
          {remaining(status, p.ledgerNow()).text}.
        </p>
      )}
      {p.canCancel && status.state === 'waiting' ? (
        <Button onClick={cancel}>This was not me: cancel the recovery</Button>
      ) : null}
    </section>
  );
}
