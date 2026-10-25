// Approve payment (exit and close): the amount, destination and deal on this screen come from the transaction's own
// bytes, decoded on the phone, and are compared with the seal the phone recomputed (P4.3-01 to 04, T-I-04).
import { Button, EmptyState, StatusBadge } from '@legx/ui';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { checkExit, signerBlob } from './-check.ts';
import { usePartyStrict } from './-context.tsx';
import { gate } from './-gate.tsx';
import { useSealedDeal } from './-sealed.ts';

const PURPOSE = { pay_bob: 'Pay Bob', refund_alice: 'Refund Alice', close: 'Close the deal wallet' } as const;
const xrp = (drops: string) =>
  `${(Number(BigInt(drops)) / 1e6).toLocaleString('en-US', { maximumFractionDigits: 6 })} XRP`;

export function ApproveScreen() {
  const s = usePartyStrict();
  const qc = useQueryClient();
  const sealed = useSealedDeal();
  const requests = useQuery({
    queryKey: ['party', s.dealId, 'requests'],
    queryFn: () => s.api.signatures.list({ dealId: s.dealId }),
  });
  const open = requests.data?.requests.find((r) => r.status === 'open' && !r.signedRoles.includes(s.role));
  const sealedData = sealed.data;
  const view = useQuery({
    queryKey: ['party', s.dealId, 'exit', open?.requestId, sealedData?.deal.dealSeal],
    enabled: Boolean(open && sealedData),
    queryFn: async () => {
      if (!open || !sealedData) throw new Error('unreachable');
      if (sealedData.state !== 'ok')
        return {
          ok: false as const,
          code: 'SEAL_MISMATCH',
          message: sealedData.state === 'incomplete' ? 'Your deal is not sealed yet.' : 'Seal mismatch',
        };
      return checkExit({
        dealId: s.dealId,
        request: open,
        publicData: sealedData.publicData as never,
        claimedSeals: [sealedData.deal.dealSeal],
        amountDrops: sealedData.deal.amountDrops,
        accountInfo: s.accountInfo,
      });
    },
  });
  const [acknowledged, setAcknowledged] = useState(false);
  const approve = useMutation({
    mutationFn: async () => {
      if (!open || !sealedData || sealedData.state !== 'ok') throw new Error('NOTHING_TO_SIGN');
      const pub = s.role === 'alice' ? sealedData.publicData.xPubA : sealedData.publicData.xPubB;
      const signature = await s.vault.signMultisig(s.dealId, open.unsignedTx); // the passkey check happens in the vault
      const blob = await signerBlob(open.unsignedTx, signature, pub);
      // Only the signer blob goes out: no share, nonce or secret ever reaches this code.
      return s.api.signatures.submit({ dealId: s.dealId, requestId: open.requestId, role: s.role, signerBlob: blob });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['party', s.dealId, 'requests'] }),
  });

  const waiting = gate(requests, sealed);
  if (waiting) return waiting;
  if (!open) return <EmptyState title="Nothing to approve">Your lawyer has not asked for a payment yet.</EmptyState>;
  const v = view.data;
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="approve-title">
      <h1 id="approve-title" className="text-2xl font-bold">
        Approve payment
      </h1>
      <p>{PURPOSE[open.purpose as keyof typeof PURPOSE] ?? open.purpose}</p>
      {!v ? <p>Checking the transaction on your phone</p> : null}
      {v?.ok === false ? (
        <div role="alert" className="flex flex-col gap-2">
          <StatusBadge status="fail" />
          <p className="font-bold">{v.message}</p>
          <p>Nothing was signed. Tell your lawyer.</p>
        </div>
      ) : null}
      {v?.ok ? (
        <>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2" aria-label="Decoded transaction">
            <dt>Amount</dt>
            <dd data-testid="amount">{v.amountDrops ? xrp(v.amountDrops) : 'Closes the wallet'}</dd>
            <dt>To</dt>
            <dd data-testid="destination" className="break-all">
              {v.destination}
              {v.tag === undefined ? '' : ` (tag ${v.tag})`}
            </dd>
            <dt>Deal</dt>
            <dd data-testid="deal" className="break-all">
              {v.dealId}
            </dd>
            <dt>From wallet</dt>
            <dd className="break-all">{v.wallet}</dd>
          </dl>
          <p>
            <StatusBadge status="pass" /> Matches the seal your phone recomputed.
          </p>
          {v.warnings.map((w) => (
            <p key={w} role="alert">
              <StatusBadge status="fail" /> {w}
            </p>
          ))}
          {v.warnings.length > 0 ? (
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={acknowledged} onChange={(e) => setAcknowledged(e.target.checked)} />I
              understand the warning
            </label>
          ) : null}
          <Button
            onClick={() => approve.mutate()}
            disabled={approve.isPending || approve.isSuccess || (v.warnings.length > 0 && !acknowledged)}
          >
            {approve.isError ? 'Try again' : 'Approve payment'}
          </Button>
        </>
      ) : null}
      {approve.isSuccess ? <p role="status">Signed. Your lawyer sees your signature.</p> : null}
      {approve.isError ? (
        <p role="alert">
          Nothing was sent: {(approve.error as { code?: string }).code ?? (approve.error as Error).message}
        </p>
      ) : null}
    </section>
  );
}
