import { Button, DealProgress } from '@legx/ui';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { createDeal, type Deal, type Participant, useDeals, useParticipants } from '../../lib/demo-deals.tsx';
import { Field, INPUT, Page, who } from '../../lib/demo-ui.tsx';
import { PhoneSignupQr } from '../../lib/phone-qr.tsx';
import { useDealStages } from '../present/-stages.tsx';
import { DealDetail } from './-detail.tsx';
import { Card, EmptyState, RidChip, Skeleton, StatusChip, when } from './-kit.tsx';

const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const size = (n: number) => (n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`);

function Dropzone() {
  const [info, setInfo] = useState<{ name: string; size: number; sha?: string }>();
  const pick = async (f?: File) => {
    if (!f) return setInfo(undefined);
    setInfo({ name: f.name, size: f.size });
    try {
      const sha = hex(await crypto.subtle.digest('SHA-256', await f.arrayBuffer()));
      setInfo({ name: f.name, size: f.size, sha });
    } catch {
      // SHA-256 is a preview only; the server hashes the file itself
    }
  };
  return (
    <div className="flex flex-col gap-2 md:col-span-2">
      <label
        htmlFor="contract-pdf"
        className="flex min-h-28 cursor-pointer flex-col items-center justify-center gap-1 rounded-xl border-2 border-dashed border-line p-4 text-center focus-within:outline-2 focus-within:outline-primary"
      >
        <span className="text-base font-semibold">
          {info ? info.name : 'Drop the contract PDF here, or click to choose'}
        </span>
        {info ? (
          <span className="text-sm text-muted">
            {size(info.size)}
            {info.sha ? (
              <>
                {' '}
                · SHA-256 <span className="break-all font-mono">{info.sha}</span>
              </>
            ) : null}
          </span>
        ) : null}
        <input
          id="contract-pdf"
          name="contractPdf"
          aria-label="Contract PDF"
          type="file"
          accept="application/pdf"
          required
          className="sr-only"
          onChange={(e) => void pick(e.target.files?.[0])}
        />
      </label>
    </div>
  );
}

function Picker({
  label,
  name,
  value,
  onChange,
  people,
}: {
  label: string;
  name: string;
  value: string;
  onChange: (v: string) => void;
  people: Participant[];
}) {
  const p = people.find((x) => x.rid === value);
  return (
    <div className="flex flex-col gap-2">
      <Field label={label}>
        <select
          name={name}
          aria-label={label}
          required
          className={INPUT}
          value={value}
          onChange={(e) => onChange(e.target.value)}
        >
          <option value="">Choose</option>
          {people.map((x) => (
            <option key={x.rid} value={x.rid}>
              {who(x)}
            </option>
          ))}
        </select>
      </Field>
      <p className="flex min-h-7 items-center gap-2 text-xl font-bold">
        {p ? <RidChip size="lg" name={p.name} rid={p.rid} fingerprint={p.fingerprint} /> : null}
      </p>
    </div>
  );
}

function CreateDeal({ onCreated }: { onCreated: (d: Deal) => void }) {
  const qc = useQueryClient();
  const people = useParticipants().data ?? [];
  const [sender, setSender] = useState('');
  const [recipient, setRecipient] = useState('');
  const create = useMutation({
    mutationFn: createDeal,
    onSuccess: (d) => {
      void qc.invalidateQueries({ queryKey: ['demo'] });
      onCreated(d);
    },
  });
  const same = sender !== '' && sender === recipient;
  return (
    <form
      aria-label="Create deal"
      className="grid gap-x-8 gap-y-3 rounded-2xl border border-line p-6 shadow-sm md:grid-cols-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (!same) create.mutate(new FormData(e.currentTarget));
      }}
    >
      <Picker label="Sender (funds the escrow)" name="senderRid" value={sender} onChange={setSender} people={people} />
      <Picker
        label="Recipient (paid on release)"
        name="recipientRid"
        value={recipient}
        onChange={setRecipient}
        people={people}
      />
      {same ? (
        <p role="alert" className="font-semibold text-fail md:col-span-2">
          Sender and recipient must differ.
        </p>
      ) : null}
      <Field label="Amount (XRP)">
        <span className="flex items-center gap-2">
          <input
            name="amountXrp"
            aria-label="Amount (XRP)"
            type="number"
            min={1}
            max={1000}
            step={1}
            required
            defaultValue={50}
            className={`${INPUT} w-full`}
          />
          <span aria-hidden="true" className="font-bold text-muted">
            XRP
          </span>
        </span>
      </Field>
      <Field label="Terms">
        <input name="terms" aria-label="Terms" required placeholder="What is being paid for" className={INPUT} />
      </Field>
      <Dropzone />
      <div className="flex items-center gap-4 md:col-span-2">
        <Button type="submit" disabled={create.isPending || same}>
          {create.isPending ? 'Creating…' : 'Create deal'}
        </Button>
        {create.error ? (
          <p role="alert" className="text-fail">
            Could not create the deal. Check the details and try again.
          </p>
        ) : null}
      </div>
    </form>
  );
}

function RowDots({ deal }: { deal: Deal }) {
  const { stages } = useDealStages(deal.id, deal);
  return <DealProgress stages={stages ?? deal.stages} compact />;
}

const ago = (d: Deal) => when(d.releasedAt ?? d.stages.findLast((s) => s.at)?.at ?? d.createdAt);

function DealList({
  status,
  open,
  setOpen,
}: {
  status: 'locked' | 'released';
  open?: string;
  setOpen: (id?: string) => void;
}) {
  const deals = useDeals(status);
  const list = deals.data ?? [];
  const sel = list.find((d) => d.id === open);
  if (sel)
    return (
      <div className="flex flex-col gap-3">
        <Button variant="outline" onClick={() => setOpen(undefined)}>
          Back to list
        </Button>
        <DealDetail deal={sel} />
      </div>
    );
  if (deals.isPending) return <Skeleton lines={4} />;
  if (list.length === 0)
    return <EmptyState title={`No ${status} escrows`}>Create a deal above and it will appear here.</EmptyState>;
  return (
    <ul className="flex flex-col gap-3">
      {list.map((d) => (
        <li key={d.id}>
          <Card className="p-4">
            <button
              type="button"
              className="flex w-full flex-wrap items-center justify-between gap-2 text-left"
              onClick={() => setOpen(d.id)}
            >
              <span className="text-xl font-bold">
                {d.sender.name} to {d.recipient.name} · {d.amountXrp} XRP
              </span>
              <span className="flex items-center gap-3">
                <StatusChip status={d.status} />
                <span className="text-sm text-muted">{ago(d)}</span>
              </span>
            </button>
            <div className="mt-2">
              <RowDots deal={d} />
            </div>
          </Card>
        </li>
      ))}
    </ul>
  );
}

function Count({ status }: { status: 'locked' | 'released' }) {
  const n = useDeals(status).data?.length;
  return <>{n === undefined ? '' : ` (${n})`}</>;
}

function Deals() {
  const [tab, setTab] = useState<'locked' | 'released'>('locked');
  const [open, setOpen] = useState<string>();
  return (
    <Page title="Deals" wide>
      <PhoneSignupQr />
      <CreateDeal
        onCreated={(d) => {
          setTab('locked');
          setOpen(d.id);
        }}
      />
      <div role="tablist" aria-label="Escrows" className="flex gap-2">
        {(['locked', 'released'] as const).map((t) => (
          <Button
            key={t}
            role="tab"
            aria-selected={tab === t}
            variant={tab === t ? 'primary' : 'outline'}
            onClick={() => {
              setTab(t);
              setOpen(undefined);
            }}
          >
            {t === 'locked' ? 'Locked escrows' : 'Released escrows'}
            <Count status={t} />
          </Button>
        ))}
      </div>
      <div role="tabpanel">
        <DealList key={tab} status={tab} open={open} setOpen={setOpen} />
      </div>
    </Page>
  );
}

export const Route = createFileRoute('/deals/')({ component: Deals });
