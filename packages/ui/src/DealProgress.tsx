import { cn } from './cn.ts';

export interface ProgressStage {
  readonly n: number;
  readonly name: string;
  readonly actor?: string;
  readonly status: 'pending' | 'done' | 'failed';
  readonly at?: string;
  readonly by?: string;
}

const DOT = {
  pending: 'border-2 border-line bg-bg text-muted',
  done: 'bg-pass text-bg',
  failed: 'bg-fail text-bg',
} as const;

const Mark = ({ status, n, show }: { status: ProgressStage['status']; n: number; show: boolean }) =>
  !show ? null : status === 'done' ? (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="size-3/5" fill="none" stroke="currentColor" strokeWidth="3">
      <path d="M5 12.5l4.5 4.5L19 7.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ) : status === 'failed' ? (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="size-3/5" fill="none" stroke="currentColor" strokeWidth="3">
      <path d="M6 6l12 12M18 6L6 18" strokeLinecap="round" />
    </svg>
  ) : (
    <span className="font-bold leading-none">{n}</span>
  );

/**
 * One dot per stage: grey pending, green done (check), red failed (cross). The current stage (`current`, else the
 * first pending one) pulses (not with reduced motion), carries a ring and aria-current="step". Never colour alone:
 * each item carries its state as text for screen readers. `compact` is a thin track for cards, naming only the
 * current stage. `large` is for a projector.
 */
export function DealProgress({
  stages,
  current,
  compact = false,
  large = false,
}: {
  stages: readonly ProgressStage[];
  current?: number;
  compact?: boolean;
  large?: boolean;
}) {
  const cur = current ?? stages.find((s) => s.status === 'pending')?.n;
  const currentStage = stages.find((s) => s.n === cur);
  const done = stages.filter((s) => s.status === 'done').length;
  if (compact)
    return (
      <div className="flex flex-col gap-2">
        <ol aria-label="Deal progress" className="flex items-center justify-between gap-1">
          {stages.map((s) => {
            const isCur = s.n === cur;
            return (
              <li
                key={s.n}
                data-status={s.status}
                data-current={isCur ? 'true' : undefined}
                aria-current={isCur ? 'step' : undefined}
                className="flex flex-1 justify-center"
              >
                <span
                  aria-hidden="true"
                  className={cn(
                    'block rounded-full',
                    isCur ? 'size-4' : 'size-3',
                    isCur && s.status === 'pending' ? 'bg-primary' : DOT[s.status],
                    isCur && 'motion-safe:animate-pulse ring-2 ring-primary ring-offset-2 ring-offset-bg',
                  )}
                />
                <span className="sr-only">{`${s.n}. ${s.name}: ${s.status}`}</span>
              </li>
            );
          })}
        </ol>
        <p className="flex justify-between gap-2 text-sm text-muted">
          <span className="font-semibold text-fg">{currentStage ? `Now: ${currentStage.name}` : 'All steps done'}</span>
          <span>
            {done}/{stages.length}
          </span>
        </p>
      </div>
    );
  return (
    <ol
      aria-label="Deal progress"
      className={cn(
        'grid gap-x-2 gap-y-4',
        large ? 'grid-cols-7 gap-y-8' : 'grid-cols-4 sm:grid-cols-7',
        large ? 'xl:grid-cols-14' : 'lg:grid-cols-7',
      )}
    >
      {stages.map((s) => {
        const isCur = s.n === cur;
        return (
          <li
            key={s.n}
            data-status={s.status}
            data-current={isCur ? 'true' : undefined}
            aria-current={isCur ? 'step' : undefined}
            className="flex flex-col items-center gap-2 text-center"
          >
            <span
              aria-hidden="true"
              className={cn(
                'flex items-center justify-center rounded-full',
                large ? 'size-16 text-2xl' : 'size-9 text-sm',
                DOT[s.status],
                isCur && 'motion-safe:animate-pulse ring-4 ring-primary ring-offset-2 ring-offset-bg',
              )}
            >
              <Mark status={s.status} n={s.n} show />
            </span>
            <span
              className={cn(
                'leading-tight',
                large ? 'text-xl' : 'text-xs sm:text-sm',
                isCur ? 'font-bold text-fg' : s.status === 'pending' ? 'text-muted' : 'text-fg',
              )}
            >
              {s.name}
              <span className="sr-only">{`: ${s.status}`}</span>
            </span>
          </li>
        );
      })}
    </ol>
  );
}
