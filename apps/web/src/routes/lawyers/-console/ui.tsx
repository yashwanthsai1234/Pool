// One half of the lawyer page. Both halves share these components with a `role` prop; each half gets its own controller
// (and so its own vault namespace). Every state shows an icon and a word, never colour alone.
import { Button, StatusBadge } from '@legx/ui';
import { createContext, type ReactNode, useContext, useId, useState, useSyncExternalStore } from 'react';
import type { Described } from './approval.ts';
import type { ChipRelay } from './chipRelay.ts';
import type { LawyerConsole } from './index.ts';
import type { Role } from './ports.ts';
import type { ApprovalPrompt } from './prompt.ts';

type Exit = { requestId: string; label: string; tx: Record<string, unknown>; claimed?: Described };
export type HalfProps = {
  console: LawyerConsole;
  prompt: ApprovalPrompt;
  /** The two lawyers' contract signatures, kept by the page so each half can see the other's public signature. */
  sigs: { LA?: Uint8Array; LB?: Uint8Array };
  onContractSigned(role: Role, sig: Uint8Array): void;
  exits?: Exit[];
  onExitSigned?(requestId: string, signatureHex: string): void;
  /** Reader helper (task 4.6): a sealed chip transfer for the QR this half is showing, or a fixture (demo profile). */
  chip?: { fixture?: () => Promise<Parameters<LawyerConsole['passport']['check']>[0]>; relay?: ChipRelay };
};
export type ConsoleWiring = {
  LA?: Omit<HalfProps, 'sigs' | 'onContractSigned'>;
  LB?: Omit<HalfProps, 'sigs' | 'onContractSigned'>;
};

const Ctx = createContext<ConsoleWiring>({});
export const useConsoleWiring = () => useContext(Ctx);

const useStore = <T,>(s: { subscribe(fn: () => void): () => void; state(): T }) =>
  useSyncExternalStore(s.subscribe, s.state);

const errorText = (e: unknown) => {
  const code = (e as { code?: string }).code;
  const msg = e instanceof Error ? e.message : String(e);
  return code === 'APPROVAL_CANCELLED' ? 'You cancelled. Nothing was signed.' : msg;
};

/** Runs an action, shows its result line or its error. */
function useAction() {
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ ok: boolean; text: string } | undefined>();
  const run = async (f: () => Promise<string | undefined>) => {
    setBusy(true);
    setNote(undefined);
    try {
      const text = await f();
      if (text) setNote({ ok: true, text });
    } catch (e) {
      setNote({ ok: false, text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };
  return { busy, note, run };
}

const Note = ({ note }: { note?: { ok: boolean; text: string } }) =>
  note ? (
    <p role={note.ok ? 'status' : 'alert'}>
      <StatusBadge status={note.ok ? 'pass' : 'fail'} /> {note.text}
    </p>
  ) : null;

const Card = ({ title, children }: { title: string; children: ReactNode }) => {
  const id = useId();
  return (
    <section aria-labelledby={id} className="flex flex-col gap-3 rounded-md border-2 border-line p-4">
      <h3 id={id} className="text-lg font-bold">
        {title}
      </h3>
      {children}
    </section>
  );
};

function ApprovalDialog({ prompt, name }: { prompt: ApprovalPrompt; name: string }) {
  const pending = useSyncExternalStore(prompt.subscribe, prompt.current);
  if (!pending) return null;
  const { view } = pending;
  const mismatch = view.mismatch.length > 0;
  return (
    <section
      role="alertdialog"
      aria-modal="true"
      aria-label={`${name}: approve this message`}
      className="flex flex-col gap-3 rounded-md border-4 border-fg p-4"
    >
      <h3 className="text-lg font-bold">Approve this message</h3>
      <p>The console read these bytes itself:</p>
      <ul className="list-disc pl-6">
        {view.lines.map((l) => (
          <li key={l}>{l}</li>
        ))}
      </ul>
      <p>
        Message hash: <code className="break-all">{view.hash}</code>
      </p>
      {mismatch ? (
        <div role="alert">
          <StatusBadge status="fail" /> The coordinator described this differently from the bytes:
          <ul className="list-disc pl-6">
            {view.mismatch.map((m) => (
              <li key={m}>{m}</li>
            ))}
          </ul>
          <p>No approval is offered for a false summary.</p>
        </div>
      ) : null}
      <div className="flex gap-3">
        {mismatch ? null : <Button onClick={() => prompt.answer(true)}>Approve with my security key</Button>}
        <Button variant="outline" onClick={() => prompt.answer(false)}>
          {mismatch ? 'Close' : 'Cancel'}
        </Button>
      </div>
    </section>
  );
}

function ContractCard({
  c,
  role,
  sigs,
  onSigned,
}: {
  c: LawyerConsole;
  role: Role;
  sigs: HalfProps['sigs'];
  onSigned: HalfProps['onContractSigned'];
}) {
  const a = useAction();
  const view = (() => {
    try {
      return c.deal.contractView();
    } catch (e) {
      return errorText(e);
    }
  })();
  return (
    <Card title="Contract">
      {typeof view === 'string' ? (
        <p role="alert">
          <StatusBadge status="fail" /> {view}
        </p>
      ) : (
        <>
          <section aria-label="Contract text">
            <p className="whitespace-pre-wrap">{view.text}</p>
          </section>
          <p>
            Deal wallet: <code>{view.wallet}</code>
          </p>
          <p>
            Contract root (computed here): <code className="break-all">{view.rootHex}</code>
          </p>
          <Button
            disabled={a.busy}
            onClick={() =>
              a.run(async () => {
                const sig = await c.deal.signContract();
                onSigned(role, sig);
                return 'Contract signed.';
              })
            }
          >
            Sign contract
          </Button>
        </>
      )}
      {role === 'LA' ? (
        <Button
          variant="outline"
          disabled={a.busy || !sigs.LA || !sigs.LB}
          onClick={() =>
            a.run(async () => {
              const r = await c.deal.mintContractNft(sigs.LA as Uint8Array, sigs.LB as Uint8Array);
              return `Contract NFT mint ${r.result}.`;
            })
          }
        >
          Mint contract NFT
        </Button>
      ) : null}
      {role === 'LA' && !(sigs.LA && sigs.LB) ? <p>Minting needs both lawyers' signatures.</p> : null}
      <Note note={a.note} />
    </Card>
  );
}

function OpsCard({ c, role }: { c: LawyerConsole; role: Role }) {
  const a = useAction();
  const [code, setCode] = useState<{ condition: string; display: string } | undefined>();
  return (
    <Card title="Operations account">
      <Button
        disabled={a.busy}
        onClick={() =>
          a.run(async () => {
            await c.deal.bindOperationsAccount();
            return 'Operations account bound and checked on the ledger.';
          })
        }
      >
        Bind operations account
      </Button>
      {role === 'LB' ? (
        <>
          <Button
            variant="outline"
            disabled={a.busy}
            onClick={() => a.run(async () => void setCode(await c.deal.makeReleaseCode()))}
          >
            Make release code
          </Button>
          {code ? (
            <div>
              <p>Release code. It stays in this browser, and goes to the ledger only inside the release.</p>
              <p>
                <output aria-label="Release code">
                  <code>{code.display}</code>
                </output>
              </p>
              <p>
                Condition sent to the coordinator: <code className="break-all">{code.condition}</code>
              </p>
            </div>
          ) : null}
        </>
      ) : null}
      <Note note={a.note} />
    </Card>
  );
}

function PassportCard({ c, role, chip }: { c: LawyerConsole; role: Role; chip: HalfProps['chip'] }) {
  const p = useStore(c.passport);
  const a = useAction();
  const [sig, setSig] = useState('');
  const who = role === 'LA' ? 'Alice' : 'Bob';
  const hint = useId();
  return (
    <Card title={`${who}'s passport`}>
      <p>
        Method: <strong>{c.passport.method === 'zkpassport' ? 'Zero-knowledge' : 'Chip'}</strong>
      </p>
      <Button disabled={a.busy} onClick={() => a.run(async () => void (await c.passport.begin()))}>
        Start check
      </Button>
      {p.presenceMsgHex ? (
        <p>
          Presence message for {who}'s phone: <code className="break-all">{p.presenceMsgHex}</code>
        </p>
      ) : null}
      {p.qr ? (
        <p>
          Reader code: <code className="break-all">{p.qr}</code>
        </p>
      ) : null}
      {p.qr && chip?.relay ? (
        <Button
          variant="outline"
          disabled={a.busy}
          onClick={() =>
            a.run(async () => {
              const relay = chip.relay as ChipRelay;
              const qr = p.qr as string;
              await relay.open(qr);
              await c.passport.check({ kind: 'reader', sealed: await relay.receive(qr) });
              return 'The phone sent the chip data.';
            })
          }
        >
          Receive from {who}'s phone
        </Button>
      ) : null}
      <Button
        disabled={a.busy || p.phase === 'idle'}
        onClick={() =>
          a.run(async () => void (await c.passport.check(chip?.fixture ? await chip.fixture() : undefined)))
        }
      >
        Check {who}'s passport
      </Button>
      {p.items.length ? (
        <ul aria-label="Passport checks" className="flex flex-col gap-1">
          {p.items.map((i) => (
            <li key={i.name}>
              <StatusBadge status={i.status} /> {i.name.replaceAll('_', ' ')}
              {i.reason ? `: ${i.reason}` : ''}
            </li>
          ))}
        </ul>
      ) : null}
      <label className="flex flex-col gap-1">
        {who}'s presence signature (hex)
        <input
          className="min-h-11 rounded-md border-2 border-line bg-bg px-2"
          value={sig}
          onChange={(e) => setSig(e.target.value.trim())}
        />
      </label>
      <Button
        variant="outline"
        disabled={sig.length !== 128 || p.phase === 'idle'}
        onClick={() =>
          a.run(async () => {
            const next = c.passport.submitPresence(
              Uint8Array.from(sig.match(/../g) ?? [], (h) => Number.parseInt(h, 16)),
            );
            return next.presence === 'valid'
              ? 'Presence signature verified.'
              : (() => {
                  throw new Error('The presence signature does not verify.');
                })();
          })
        }
      >
        Check presence signature
      </Button>
      <Button
        disabled={a.busy || !p.canSign}
        aria-describedby={p.canSign ? undefined : hint}
        onClick={() =>
          a.run(async () => {
            await c.passport.sign();
            return 'Attestation signed. The passport data was dropped.';
          })
        }
      >
        Sign attestation
      </Button>
      {!p.canSign && p.phase !== 'signed' ? <p id={hint}>{p.blocked ?? 'Start the check first.'}</p> : null}
      <Note note={a.note} />
    </Card>
  );
}

function GateCard({ c, role }: { c: LawyerConsole; role: Role }) {
  const g = useStore(c.gate);
  const a = useAction();
  const hint = useId();
  return (
    <Card title="Release gate">
      <Button disabled={a.busy || g.status === 'running'} onClick={() => a.run(async () => void (await c.gate.run()))}>
        {role === 'LB' ? 'Run lock check and release gate' : 'Run release gate'}
      </Button>
      {g.status === 'refused' && g.refusal ? (
        <p role="alert">
          <StatusBadge status="fail" /> {g.refusal.reason}
        </p>
      ) : null}
      {g.status === 'done' ? (
        <>
          <p>
            Ledger {g.ledger?.index}. Alice: {g.methods.A.label}. Bob: {g.methods.B.label}.
          </p>
          <ul aria-label="Release gate findings" className="flex flex-col gap-1">
            {g.findings.map((f) => (
              <li key={f.code}>
                <StatusBadge status={f.ok ? 'pass' : 'fail'} /> <code>{f.code}</code>
                {f.detail ? `: ${f.detail}` : ''}
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {role === 'LB' ? (
        <>
          <Button
            disabled={a.busy || !g.canRelease}
            aria-describedby={g.canRelease ? undefined : hint}
            onClick={() =>
              a.run(async () => {
                const r = await c.gate.release();
                return `Released. Transaction ${r.hash} in ledger ${r.ledgerIndex}.`;
              })
            }
          >
            Release money
          </Button>
          {!g.canRelease ? <p id={hint}>{g.reason ?? 'Run the release gate first.'}</p> : null}
        </>
      ) : null}
      <Note note={a.note} />
    </Card>
  );
}

function ExitCard({ c, exits, onSigned }: { c: LawyerConsole; exits: Exit[]; onSigned: HalfProps['onExitSigned'] }) {
  const a = useAction();
  return (
    <Card title="Exits">
      {exits.length === 0 ? <p>No exit waits for your approval.</p> : null}
      {exits.map((x) => (
        <Button
          key={x.requestId}
          variant="outline"
          disabled={a.busy}
          onClick={() =>
            a.run(async () => {
              const signature = await c.deal.approveExit(x.tx, x.claimed); // awaited before the optional call, which would skip it
              onSigned?.(x.requestId, signature);
              return 'Exit approved.';
            })
          }
        >
          Approve exit: {x.label}
        </Button>
      ))}
      <Note note={a.note} />
    </Card>
  );
}

function LawyerHalf(p: HalfProps & { role: Role }) {
  const name = p.role === 'LA' ? 'Lawyer A' : 'Lawyer B';
  const id = useId();
  return (
    <section aria-labelledby={id} className="flex min-w-0 flex-1 flex-col gap-4 p-4">
      <h2 id={id} className="text-2xl font-bold">
        {name}
      </h2>
      <ApprovalDialog prompt={p.prompt} name={name} />
      <ContractCard c={p.console} role={p.role} sigs={p.sigs} onSigned={p.onContractSigned} />
      <OpsCard c={p.console} role={p.role} />
      <PassportCard c={p.console} role={p.role} chip={p.chip} />
      <GateCard c={p.console} role={p.role} />
      <ExitCard c={p.console} exits={p.exits ?? []} onSigned={p.onExitSigned} />
    </section>
  );
}

/** Both lawyers on one laptop: two halves side by side, with the contract signatures passed between them. */
export function LawyerConsolePage({ wiring }: { wiring: ConsoleWiring }) {
  const [sigs, setSigs] = useState<HalfProps['sigs']>({});
  const roles = (['LA', 'LB'] as const).filter((r) => wiring[r]);
  return (
    <main className="min-h-dvh bg-bg text-fg">
      <h1 className="p-4 text-3xl font-bold">Lawyer console</h1>
      <div className="flex flex-col lg:flex-row">
        {roles.map((r) => (
          <LawyerHalf
            key={r}
            role={r}
            {...(wiring[r] as NonNullable<ConsoleWiring[Role]>)}
            sigs={sigs}
            onContractSigned={(who, sig) => setSigs((s) => ({ ...s, [who]: sig }))}
          />
        ))}
      </div>
    </main>
  );
}
