// The refresh screen (P4.7-12, P4.7-22): it says up front that a refresh is hygiene, not revocation, names a dealer
// whose sub-share fails its check, and shows "refresh complete" only when every remaining holder's deletion statement
// is in.
import type { FrostRefreshed } from '@legx/core/frostRefresh';
import { Button, StatusBadge } from '@legx/ui';
import type { RefreshEvent } from '@legx/vault/frost/refresh';
import { HYGIENE_NOTE } from '@legx/vault/frost/text';
import { useState } from 'react';

export type RefreshScreenProps = { run: (onEvent: (e: RefreshEvent) => void) => Promise<FrostRefreshed> };

export function RefreshScreen(p: RefreshScreenProps) {
  const [events, setEvents] = useState<RefreshEvent[]>([]);
  const [record, setRecord] = useState<FrostRefreshed>();
  const [running, setRunning] = useState(false);
  const aborted = events.find((e) => e.kind === 'aborted') as Extract<RefreshEvent, { kind: 'aborted' }> | undefined;
  const deletions = events.filter((e) => e.kind === 'deletions').at(-1) as
    | Extract<RefreshEvent, { kind: 'deletions' }>
    | undefined;
  const start = async () => {
    setRunning(true);
    setRecord(await p.run((e) => setEvents((xs) => [...xs, e])).catch(() => undefined));
    setRunning(false);
  };
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="refresh-title">
      <h1 id="refresh-title" className="text-2xl font-bold">
        Refresh the shares
      </h1>
      <p role="note">{HYGIENE_NOTE}</p>
      <p className="text-muted">The refresh and repair code is ours and has had no independent audit.</p>
      <Button onClick={start} disabled={running || !!record}>
        Start the refresh
      </Button>
      {events.some((e) => e.kind === 'refreshed') ? <p>New shares are stored on this device.</p> : null}
      {aborted ? (
        <p role="alert">
          Refresh stopped{aborted.culprit ? `: ${aborted.culprit} sent a share that fails its check` : ''}. Your shares
          did not change.
        </p>
      ) : null}
      {deletions ? (
        <ul aria-label="Deletion statements">
          {deletions.have.map((h) => (
            <li key={h}>
              <StatusBadge status="pass" /> {h} deleted the old share
            </li>
          ))}
          {deletions.missing.map((h) => (
            <li key={h}>
              <StatusBadge status="pending" /> waiting for {h}
            </li>
          ))}
        </ul>
      ) : null}
      {record?.status === 'COMPLETE' ? <p role="status">Refresh complete.</p> : null}
      {record?.status === 'INCOMPLETE' ? (
        <p role="status">Not complete yet: old shares still work together until every holder deletes them.</p>
      ) : null}
    </section>
  );
}
