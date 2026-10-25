import { type LiveFeedOptions, type LiveStatus, useLiveDeal } from './live.ts';

const LABEL: Record<LiveStatus, string> = {
  connecting: 'Connecting',
  open: 'Live',
  reconnecting: 'Reconnecting',
  closed: 'Disconnected',
};

/** The newest deal state and the connection status. "Reconnecting" is announced politely to screen readers. */
export function LiveDealStatus(props: { dealId: string } & Pick<LiveFeedOptions, 'url' | 'backoffMs'>) {
  const { dealId, ...options } = props;
  const { status, state } = useLiveDeal(dealId, options);
  return (
    <section aria-label="Live deal state">
      <p>
        Deal state: <strong>{state ?? 'waiting'}</strong>
      </p>
      <p role="status">{LABEL[status]}</p>
    </section>
  );
}
