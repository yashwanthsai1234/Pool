// Bob's "Ship" screen and Alice's "Confirm delivery" screen (build/SHIP_RECEIPT.md section 6). Both ask for a clear
// confirmation that shows exactly what is signed before the vault is asked to sign anything.
import { Button, EmptyState, StatusBadge } from '@legx/ui';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useId, useMemo, useState } from 'react';
import { type Condition, type Manifest, type ManifestItem, usePartyStrict } from './-context.tsx';
import { gate } from './-gate.tsx';

const short = (hex: string) => (hex.length > 20 ? `${hex.slice(0, 10)}...${hex.slice(-8)}` : hex);

/** Shows what will be signed and signs only on the second tap. */
function Confirm(p: {
  title: string;
  rows: [string, string][];
  action: string;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const id = useId();
  return (
    <div role="dialog" aria-modal="true" aria-labelledby={id} className="flex flex-col gap-3 rounded border p-4">
      <h2 id={id} className="text-xl font-bold">
        {p.title}
      </h2>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2" aria-label="What you sign">
        {p.rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt>{k}</dt>
            <dd className="break-all" data-testid={`confirm-${k.toLowerCase().replaceAll(' ', '-')}`}>
              {v}
            </dd>
          </div>
        ))}
      </dl>
      <Button onClick={p.onConfirm} disabled={p.busy}>
        {p.action}
      </Button>
      <Button onClick={p.onCancel} disabled={p.busy}>
        Cancel
      </Button>
    </div>
  );
}

const blank = (): ManifestItem => ({ sku: '', description: '', qty: 1, weight_g: 0 });

function Field(p: {
  label: string;
  value: string | number;
  onChange: (v: string) => void;
  type?: string;
  min?: number;
}) {
  const id = useId();
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id}>{p.label}</label>
      <input
        id={id}
        className="border p-1"
        type={p.type ?? 'text'}
        min={p.min}
        value={p.value}
        onChange={(e) => p.onChange(e.target.value)}
      />
    </div>
  );
}

export function ShipScreen() {
  const s = usePartyStrict();
  const [items, setItems] = useState<ManifestItem[]>([blank()]);
  const [carrier, setCarrier] = useState('');
  const [trackingId, setTrackingId] = useState('');
  const [confirming, setConfirming] = useState(false);
  const manifest: Manifest = useMemo(
    () => ({
      items,
      packed_at: `${new Date().toISOString().slice(0, 19)}Z`,
      total_weight_g: items.reduce((n, i) => n + i.qty * i.weight_g, 0),
    }),
    [items],
  );
  const ready = items.every((i) => i.sku && i.description && i.qty > 0 && i.weight_g >= 0) && carrier && trackingId;
  const root = useMemo(() => {
    try {
      return s.ship?.manifestRoot(manifest);
    } catch {
      return undefined;
    }
  }, [s.ship, manifest]);
  const sign = useMutation({
    mutationFn: () => {
      if (!s.ship) throw new Error('NOT_AVAILABLE');
      return s.ship.signShipment({ manifest, carrier, trackingId });
    },
  });
  if (s.role !== 'bob') return <EmptyState title="Only Bob ships">Alice confirms delivery instead.</EmptyState>;
  if (!s.ship)
    return (
      <EmptyState title="Ship">
        This device cannot sign a shipment yet. Your lawyer will tell you when it can.
      </EmptyState>
    );
  const set = (n: number, patch: Partial<ManifestItem>) =>
    setItems((xs) => xs.map((x, i) => (i === n ? { ...x, ...patch } : x)));
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="ship-title">
      <h1 id="ship-title" className="text-2xl font-bold">
        Ship
      </h1>
      {items.map((it, n) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: rows are positional (the manifest is ordered)
        <fieldset key={n} className="flex flex-col gap-2 rounded border p-3">
          <legend>Item {n + 1}</legend>
          <Field label="SKU" value={it.sku} onChange={(v) => set(n, { sku: v })} />
          <Field label="Description" value={it.description} onChange={(v) => set(n, { description: v })} />
          <Field label="Quantity" type="number" min={1} value={it.qty} onChange={(v) => set(n, { qty: Number(v) })} />
          <Field
            label="Weight (g)"
            type="number"
            min={0}
            value={it.weight_g}
            onChange={(v) => set(n, { weight_g: Number(v) })}
          />
        </fieldset>
      ))}
      <Button onClick={() => setItems((xs) => [...xs, blank()])}>Add item</Button>
      <Field label="Carrier" value={carrier} onChange={setCarrier} />
      <Field label="Tracking ID" value={trackingId} onChange={setTrackingId} />
      <p>Total weight: {manifest.total_weight_g} g</p>
      <p className="break-all" data-testid="manifest-root">
        Manifest root: {root ?? 'not valid yet'}
      </p>
      {confirming && root ? (
        <Confirm
          title="Sign this shipment?"
          rows={[
            ['Manifest root', root],
            ['Carrier', carrier],
            ['Tracking', trackingId],
            ['Condition', 'Packed and handed to the carrier'],
          ]}
          action="Confirm and sign"
          busy={sign.isPending}
          onConfirm={() => sign.mutate()}
          onCancel={() => setConfirming(false)}
        />
      ) : (
        <Button onClick={() => setConfirming(true)} disabled={!ready || !root || sign.isSuccess}>
          Sign shipment
        </Button>
      )}
      {sign.isSuccess ? (
        <p role="status">
          <StatusBadge status="pass" /> Shipped: you signed. Signature {short(sign.data.signature)}.
        </p>
      ) : null}
      {sign.isError ? (
        <p role="alert">
          <StatusBadge status="fail" /> Nothing was signed:{' '}
          {(sign.error as { code?: string }).code ?? (sign.error as Error).message}
        </p>
      ) : null}
    </section>
  );
}

const CONDITIONS: { id: Condition; label: string }[] = [
  { id: 'ok', label: 'Arrived and as described (ok)' },
  { id: 'damaged', label: 'Arrived damaged' },
  { id: 'missing', label: 'Did not arrive or items missing' },
];

export function ReceiveScreen() {
  const s = usePartyStrict();
  const shipment = useQuery({
    queryKey: ['party', s.dealId, 'shipment'],
    queryFn: async () => (await s.ship?.shipment()) ?? null,
    enabled: Boolean(s.ship),
  });
  const [condition, setCondition] = useState<Condition>('ok');
  const [confirming, setConfirming] = useState(false);
  const sign = useMutation({
    mutationFn: () => {
      if (!s.ship) throw new Error('NOT_AVAILABLE');
      return s.ship.signReceipt({ condition });
    },
  });
  if (s.role !== 'alice') return <EmptyState title="Only Alice confirms delivery">Bob ships instead.</EmptyState>;
  if (!s.ship)
    return (
      <EmptyState title="Confirm delivery">
        This device cannot sign a receipt yet. Your lawyer will tell you when it can.
      </EmptyState>
    );
  const waiting = gate(shipment);
  if (waiting) return waiting;
  const rec = shipment.data;
  if (!rec) return <EmptyState title="Nothing shipped yet">Bob has not signed a shipment.</EmptyState>;
  let recomputed: string | undefined;
  try {
    recomputed = s.ship.manifestRoot(rec.manifest);
  } catch {
    recomputed = undefined;
  }
  const matches = recomputed === rec.signedRoot;
  const dispute = condition !== 'ok';
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="receive-title">
      <h1 id="receive-title" className="text-2xl font-bold">
        Confirm delivery
      </h1>
      <ul aria-label="Manifest" className="flex flex-col gap-1">
        {rec.manifest.items.map((i) => (
          <li key={i.sku}>
            {i.qty} x {i.description} ({i.sku}), {i.weight_g} g each
          </li>
        ))}
      </ul>
      <p>Total weight: {rec.manifest.total_weight_g} g</p>
      <p>Carrier: {rec.carrier}</p>
      <p>Tracking: {rec.trackingId}</p>
      <p className="break-all">Signed manifest root: {rec.signedRoot}</p>
      {matches ? (
        <p role="status" data-testid="root-check">
          <StatusBadge status="pass" /> This manifest matches the root Bob signed.
        </p>
      ) : (
        <p role="alert" data-testid="root-check">
          <StatusBadge status="fail" /> Mismatch: this manifest does not match the root Bob signed. Do not sign. Tell
          your lawyer.
        </p>
      )}
      <fieldset className="flex flex-col gap-2">
        <legend>Condition</legend>
        {CONDITIONS.map((c) => (
          <label key={c.id} className="flex items-center gap-2">
            <input type="radio" name="condition" checked={condition === c.id} onChange={() => setCondition(c.id)} />
            {c.label}
          </label>
        ))}
      </fieldset>
      {dispute ? (
        <p role="note" data-testid="dispute-path">
          The money is not released on a {condition} receipt. Your lawyer opens a dispute and both lawyers decide.
        </p>
      ) : null}
      {confirming && matches ? (
        <Confirm
          title="Sign this receipt?"
          rows={[
            ['Manifest root', rec.signedRoot],
            ['Carrier', rec.carrier],
            ['Tracking', rec.trackingId],
            ['Condition', condition],
          ]}
          action="Confirm and sign"
          busy={sign.isPending}
          onConfirm={() => sign.mutate()}
          onCancel={() => setConfirming(false)}
        />
      ) : (
        <Button onClick={() => setConfirming(true)} disabled={!matches || sign.isSuccess}>
          Sign receipt
        </Button>
      )}
      {sign.isSuccess ? (
        <p role="status">
          <StatusBadge status="pass" /> Received: you signed ({condition}). Signature {short(sign.data.signature)}.
        </p>
      ) : null}
      {sign.isError ? (
        <p role="alert">
          <StatusBadge status="fail" /> Nothing was signed:{' '}
          {(sign.error as { code?: string }).code ?? (sign.error as Error).message}
        </p>
      ) : null}
    </section>
  );
}
