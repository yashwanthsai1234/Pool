import { CircleCheck, CircleX, Clock } from 'lucide-react';
import { cn } from './cn.ts';

export type Status = 'pass' | 'fail' | 'pending';

// Never colour alone (WCAG 1.4.1): every state has an icon AND a text label.
const STATES = {
  pass: { Icon: CircleCheck, label: 'PASS', tone: 'text-pass' },
  fail: { Icon: CircleX, label: 'FAIL', tone: 'text-fail' },
  pending: { Icon: Clock, label: 'PENDING', tone: 'text-muted' },
} as const;

export function StatusBadge({ status, className }: { status: Status; className?: string }) {
  const { Icon, label, tone } = STATES[status];
  return (
    <span data-status={status} className={cn('inline-flex items-center gap-2 font-bold', tone, className)}>
      <Icon aria-hidden="true" className="size-5" />
      {label}
    </span>
  );
}
