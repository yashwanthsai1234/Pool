// Local presentation primitives for /deals and /present (swap for demo-ui.tsx's once those are final).
import { Card, StatusChip as Chip, EmptyState, RidChip, Skeleton } from '../../lib/demo-ui.tsx';

export { Card, EmptyState, RidChip, Skeleton };
export const StatusChip = Chip;

const cx = (...c: (string | false | undefined)[]) => c.filter(Boolean).join(' ');

export const Lock = ({ open, className = 'size-5' }: { open?: boolean; className?: string }) => (
  <svg aria-hidden="true" viewBox="0 0 24 24" className={className} fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="5" y="11" width="14" height="10" rx="2" />
    <path d={open ? 'M8 11V7a4 4 0 0 1 7.5-2' : 'M8 11V7a4 4 0 0 1 8 0v4'} />
  </svg>
);
const Check = () => (
  <svg aria-hidden="true" viewBox="0 0 24 24" className="size-5" fill="none" stroke="currentColor" strokeWidth="3">
    <path d="M5 12l5 5 9-10" />
  </svg>
);

function BigChip({ status }: { status: 'locked' | 'released' | 'failed' }) {
  const large = true;
  const tone =
    status === 'locked'
      ? 'border-amber-500 text-fg [&_svg]:text-amber-500'
      : status === 'released'
        ? 'border-pass text-pass'
        : 'border-fail text-fail';
  return (
    <span
      data-chip={status}
      className={cx(
        'inline-flex items-center gap-1.5 rounded-full border-2 px-3 py-0.5 font-bold capitalize',
        large ? 'text-2xl' : 'text-sm',
        tone,
      )}
    >
      {status === 'locked' ? <Lock /> : status === 'released' ? <Check /> : null}
      {status}
    </span>
  );
}

export { BigChip };
export const money = (n: number) => `${n} XRP`;
export const when = (iso?: string) => (iso ? new Date(iso).toLocaleString() : '');
