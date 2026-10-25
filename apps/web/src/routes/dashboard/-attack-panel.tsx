import { Button, StatusBadge } from '@legx/ui';
import { useEffect, useState } from 'react';
import { ATTACKS, type AttackClient, type AttackId, type AttackResult } from './-attack-api.ts';
import { explorerUrl, type Network } from './-explorer.ts';
import { Panel } from './-panels.tsx';

/**
 * Attack mode. Renders nothing unless the server answers the attack list, which only the demo profile does (P4.5-04).
 * The buttons post to `/demo/attack/*`; the result shows the ledger's engine code or the check that stopped the attack.
 */
export function AttackPanel({
  client,
  network,
  onResult,
}: {
  client: AttackClient;
  network: Network;
  onResult: (r: AttackResult | undefined) => void;
}) {
  const [on, setOn] = useState(false);
  const [busy, setBusy] = useState<AttackId | undefined>();
  const [result, setResult] = useState<AttackResult | undefined>();
  const [error, setError] = useState<string | undefined>();

  useEffect(() => {
    let live = true;
    void client.available().then((ok) => live && setOn(ok));
    return () => {
      live = false;
    };
  }, [client]);

  if (!on) return null;
  const run = async (id: AttackId) => {
    setBusy(id);
    setError(undefined);
    try {
      const r = await client.run(id);
      setResult(r);
      onResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(undefined);
    }
  };
  const url = result?.txHash ? explorerUrl(network, 'tx', result.txHash) : undefined;
  return (
    <Panel title="Attack mode" className="border-fail">
      <ul className="grid gap-2">
        {ATTACKS.map((a) => (
          <li key={a.id}>
            <Button
              variant="outline"
              className="w-full justify-start text-lg"
              disabled={busy !== undefined}
              onClick={() => void run(a.id)}
            >
              {busy === a.id ? 'Running…' : a.label}
            </Button>
          </li>
        ))}
      </ul>
      <div role="status" aria-live="polite" className="mt-3 min-h-24 text-lg" data-testid="attack-result">
        {error ? <p className="text-fail">{error}</p> : null}
        {result ? (
          <>
            <p className="flex items-center gap-3">
              <StatusBadge status={result.defeated ? 'pass' : 'fail'} />
              <span className="font-bold">{result.defeated ? 'Attack stopped' : 'Attack NOT stopped'}</span>
            </p>
            <p>
              Code:{' '}
              <span className="font-mono font-bold" data-testid="attack-code">
                {result.code}
              </span>
            </p>
            <p className="text-base text-muted">{result.detail}</p>
            {url ? (
              <a href={url} target="_blank" rel="noreferrer" className="font-mono text-primary underline">
                {result.txHash?.slice(0, 12)}…
              </a>
            ) : null}
          </>
        ) : null}
      </div>
    </Panel>
  );
}
