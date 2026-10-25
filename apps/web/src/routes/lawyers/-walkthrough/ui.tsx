// The "New deal" form and the "Deal walkthrough" stepper on /lawyers (demo profile). Large type for a projector; there is no
// animation, so prefers-reduced-motion has nothing to switch off. Run is enabled only for the next step; Run all paces the
// steps with a short pause and stops at the first error.
// Source: build/WALKTHROUGH.md "Web"
import { Button, StatusBadge } from '@legx/ui';
import { useEffect, useState } from 'react';
import { explorerUrl, type Network } from '../../dashboard/-explorer.ts';
import {
  type Created,
  httpWalkthroughClient,
  type StepResult,
  type WalkthroughClient,
  type WalkthroughForm,
} from './api.ts';

const defaultClient = httpWalkthroughClient();
const field = 'min-h-11 rounded-md border-2 border-line bg-bg px-3 text-xl text-fg';
const failed = (r: StepResult | undefined) => r?.status === 'failed' || r?.status === 'error';

function Form({ onCreate }: { onCreate: (f: WalkthroughForm) => Promise<void> }) {
  const [error, setError] = useState<string | undefined>();
  return (
    <form
      className="flex flex-wrap items-end gap-4 text-xl"
      onSubmit={(e) => {
        e.preventDefault();
        const d = new FormData(e.currentTarget);
        setError(undefined);
        onCreate({
          amountXrp: 50,
          identity: d.get('identity') === 'chip' ? 'chip' : 'zk',
        }).catch((err: unknown) => setError(`The deal was not created: ${err instanceof Error ? err.message : err}`));
      }}
    >
      <label className="flex flex-col gap-1">
        Amount (XRP)
        <input name="amount" value="50" readOnly aria-describedby="amount-note" className={field} />
      </label>
      <p id="amount-note" className="self-end pb-2">
        Fixed at 50 XRP in the demo.
      </p>
      <label className="flex flex-col gap-1">
        Identity
        <select name="identity" className={field}>
          <option value="zk">Passport (zero-knowledge)</option>
          <option value="chip">Passport chip</option>
        </select>
      </label>
      <Button type="submit">Create deal</Button>
      {error && (
        <p role="alert" className="w-full font-bold text-fail">
          {error}
        </p>
      )}
    </form>
  );
}

function Hash({ hash, network }: { hash: string; network: Network }) {
  const url = explorerUrl(network, 'tx', hash);
  return url ? (
    <a href={url} target="_blank" rel="noreferrer" className="break-all underline">
      {hash}
    </a>
  ) : (
    <span className="break-all">{hash}</span>
  );
}

function Result({ r, network }: { r: StepResult; network: Network }) {
  return (
    <div className="mt-1 flex flex-col gap-1 text-lg">
      {r.detail && <p>{r.detail}</p>}
      {r.ledgerIndex !== undefined && <p>Ledger {r.ledgerIndex}</p>}
      {r.txHashes.map((h) => (
        <p key={h} className="font-mono text-base">
          <Hash hash={h} network={network} />
        </p>
      ))}
      {r.gate && (
        <ul>
          {r.gate.map((f) => (
            <li key={f.code} className="flex gap-2">
              <StatusBadge status={f.ok ? 'pass' : 'fail'} /> {f.code}
              {f.detail ? `: ${f.detail}` : ''}
            </li>
          ))}
        </ul>
      )}
      {r.bob && (
        <p className="font-bold">
          Bob before: {r.bob.before} XRP, after: {r.bob.after} XRP
        </p>
      )}
    </div>
  );
}

function Stepper({
  deal,
  client,
  network,
  pauseMs,
}: {
  deal: Created;
  client: WalkthroughClient;
  network: Network;
  pauseMs: number;
}) {
  const [results, setResults] = useState<StepResult[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [failedStep, setFailedStep] = useState<number | undefined>();
  const total = deal.steps.length;
  const done = results.length;

  /** Runs step `at` (0-based). True when the server completed it. */
  const runStep = async (at: number): Promise<boolean> => {
    try {
      const r = await client.next(deal.id);
      if (failed(r)) throw new Error(r.detail ?? r.status);
      setFailedStep(undefined);
      setResults((prev) => [...prev, r]);
      return true;
    } catch (e) {
      setFailedStep(at);
      setError(`Step ${at + 1} failed: ${e instanceof Error ? e.message : e}`);
      return false;
    }
  };

  const run = async (all: boolean) => {
    setBusy(true);
    setError(undefined);
    for (let at = done; at < (all ? total : done + 1); at++) {
      if (at > done) await new Promise((r) => setTimeout(r, pauseMs));
      if (!(await runStep(at))) break;
    }
    setBusy(false);
  };

  return (
    <section aria-labelledby="walkthrough-title" className="flex flex-col gap-3 text-xl">
      <h2 id="walkthrough-title" className="text-3xl font-bold">
        Deal walkthrough
      </h2>
      <p>
        Deal <span className="break-all font-mono">{deal.dealId}</span>. Party and lawyer keys run inside the server
        (simulated phone).
      </p>
      <div>
        <Button onClick={() => void run(true)} disabled={busy || done >= total}>
          Run all
        </Button>
      </div>
      {error && (
        <p role="alert" className="font-bold text-fail">
          {error}
        </p>
      )}
      <ol className="flex flex-col gap-3">
        {deal.steps.map((s, i) => {
          const r = results[i];
          const state = r ? 'done' : failedStep === i ? 'failed' : i === done ? 'next' : 'waiting';
          return (
            <li key={s.n} data-testid={`step-${i + 1}`} className="flex flex-col gap-1 border-b-2 border-line pb-3">
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-bold">
                  {i + 1}. {s.title}
                </span>
                <span>
                  <StatusBadge status={state === 'done' ? 'pass' : state === 'failed' ? 'fail' : 'pending'} /> {state}
                </span>
                <Button
                  variant="outline"
                  aria-label={`Run step ${i + 1}`}
                  disabled={busy || i !== done}
                  onClick={() => void run(false)}
                >
                  Run
                </Button>
              </div>
              {r && <Result r={r} network={network} />}
            </li>
          );
        })}
      </ol>
    </section>
  );
}

export function Walkthrough({
  client = defaultClient,
  network = 'standalone',
  pauseMs = 800,
}: {
  client?: WalkthroughClient;
  network?: Network;
  pauseMs?: number;
}) {
  const [on, setOn] = useState(false);
  const [open, setOpen] = useState(false);
  const [deal, setDeal] = useState<Created | undefined>();
  useEffect(() => {
    let live = true;
    void client.available().then((ok) => live && setOn(ok));
    return () => {
      live = false;
    };
  }, [client]);
  if (!on) return null;
  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-5 p-4">
      <div>
        <Button onClick={() => setOpen(true)} aria-expanded={open}>
          New deal
        </Button>
      </div>
      {open && (
        <Form
          onCreate={async (f) => {
            setDeal(await client.create(f));
          }}
        />
      )}
      {deal && <Stepper key={deal.id} deal={deal} client={client} network={network} pauseMs={pauseMs} />}
    </div>
  );
}
