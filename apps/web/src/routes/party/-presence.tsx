// Passport presence (DESIGN 6.15): the client's slot key signs `presenceMsg` while the lawyer checks the passport. The
// message is built on the phone from the seal it recomputed and the lawyer's request; the signature is checked against the
// slot key before it is sent (P4.3-05, P4.3-09).
import { presenceMsg } from '@legx/core/attest';
import { bytesToHex, hexToBytes } from '@legx/core/dealcore';
import { Button, EmptyState, StatusBadge } from '@legx/ui';
import { ed25519 } from '@noble/curves/ed25519.js';
import { useMutation, useQuery } from '@tanstack/react-query';
import { usePartyStrict } from './-context.tsx';
import { gate } from './-gate.tsx';
import { useSealedDeal } from './-sealed.ts';

const ALLOWS = { zk: ['zkpassport'], chip: ['nfc-chip'], 'zk-or-chip': ['zkpassport', 'nfc-chip'] } as const;
const LABEL = { zkpassport: 'Zero-knowledge passport check', 'nfc-chip': 'Passport chip check' } as const;

export function PresenceScreen() {
  const s = usePartyStrict();
  const sealed = useSealedDeal();
  const request = useQuery({ queryKey: ['party', s.dealId, 'presence'], queryFn: s.presenceRequest });
  const side = s.role === 'alice' ? 'A' : 'B';
  const sign = useMutation({
    mutationFn: async () => {
      const d = sealed.data;
      if (d?.state !== 'ok' || !request.data) throw new Error('NOT_READY');
      const r = request.data;
      const msg = presenceMsg(hexToBytes(d.seal), side, hexToBytes(r.ledgerHash), hexToBytes(r.lawyerNonce));
      const signature = await s.vault.signFrost(s.dealId, {
        kind: 'tagged',
        tag: 'legx/passport-presence/v1',
        parts: [
          hexToBytes(d.seal),
          new TextEncoder().encode(side),
          hexToBytes(r.ledgerHash),
          hexToBytes(r.lawyerNonce),
        ],
      });
      const pub = hexToBytes(side === 'A' ? d.publicData.xPubA : d.publicData.xPubB).slice(1);
      if (!ed25519.verify(signature, msg, pub, { zip215: false })) throw new Error('SIGNATURE_INVALID');
      await s.submitPresence({
        signature: bytesToHex(signature),
        ledgerIndex: r.ledgerIndex,
      });
      return r.ledgerIndex;
    },
  });

  const waiting = gate(sealed, request);
  if (waiting) return waiting;
  const d = sealed.data;
  if (!d || !request.data)
    return <EmptyState title="No presence check yet">Your lawyer has not started one.</EmptyState>;
  const method = request.data.method;
  const allowed = ALLOWS[d.deal.identityPolicy].some((m) => m === method);
  const problem =
    d.state === 'seal-mismatch'
      ? 'Seal mismatch'
      : d.state === 'incomplete'
        ? 'Your deal is not sealed yet.'
        : !allowed
          ? 'Your deal does not allow this method.'
          : undefined;
  return (
    <section className="mx-auto flex max-w-md flex-col gap-4 p-4" aria-labelledby="presence-title">
      <h1 id="presence-title" className="text-2xl font-bold">
        Passport presence
      </h1>
      <p data-testid="method">{LABEL[method]}</p>
      <p>Your lawyer is checking your passport.</p>
      {problem ? (
        <p role="alert">
          <StatusBadge status="fail" /> {problem} Nothing was signed.
        </p>
      ) : (
        <Button onClick={() => sign.mutate()} disabled={sign.isPending || sign.isSuccess}>
          {sign.isError ? 'Try again' : 'Confirm with your passkey'}
        </Button>
      )}
      {sign.isSuccess ? <p role="status">Signed at ledger {sign.data}.</p> : null}
      {sign.isError ? (
        <p role="alert">Nothing was sent: {(sign.error as { code?: string }).code ?? (sign.error as Error).message}</p>
      ) : null}
    </section>
  );
}
