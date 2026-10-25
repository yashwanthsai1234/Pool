// Shared primitives of the product demo screens (build/UX.md). Inline SVG icons only; tokens from @legx/ui/theme.css.
import { Button, cn } from '@legx/ui';
import { useRouterState } from '@tanstack/react-router';
import { type ReactNode, useCallback, useEffect, useId, useRef, useState } from 'react';
import type { Participant } from './demo-deals.tsx';

/** sessionStorage key: /register sets it, /me greets the new participant once. */
export const WELCOME_KEY = 'legx.demo.welcome';

export const shortRid = (rid: string) => `${rid.slice(0, 8)}…`;
export const who = (p: Participant) => `${p.name} · ${shortRid(p.rid)}`;

/* ---------- icons ---------- */
const svg = (d: ReactNode, cls = 'size-5') => (
  <svg
    aria-hidden="true"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2.25"
    strokeLinecap="round"
    strokeLinejoin="round"
    className={cn('shrink-0', cls)}
  >
    {d}
  </svg>
);
export const Icon = {
  check: (c?: string) => svg(<path d="M5 12.5l4.5 4.5L19 7.5" />, c),
  x: (c?: string) => svg(<path d="M6 6l12 12M18 6L6 18" />, c),
  lock: (c?: string) =>
    svg(
      <>
        <rect x="5" y="11" width="14" height="10" rx="2" />
        <path d="M8 11V7a4 4 0 018 0v4" />
      </>,
      c,
    ),
  clock: (c?: string) =>
    svg(
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 2" />
      </>,
      c,
    ),
  copy: (c?: string) =>
    svg(
      <>
        <rect x="9" y="9" width="11" height="11" rx="2" />
        <path d="M5 15V6a2 2 0 012-2h9" />
      </>,
      c,
    ),
  arrow: (c?: string) => svg(<path d="M5 12h14M13 6l6 6-6 6" />, c),
  external: (c?: string) =>
    svg(<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V7a1 1 0 011-1h5" />, c),
  hand: (c?: string) => svg(<path d="M12 3v9M8 7v6M16 6v7M4 12c0 5 3.5 9 8 9s8-3 8-8V8" />, c),
};

/* ---------- page frame ---------- */

/** The one honest line every demo screen carries. */
export const DemoLabel = () => <p className="text-xs text-muted">demo: keys held by the server</p>;

/** The demo's pages, so nobody has to type a URL. */
export const NAV_LINKS = [
  ['/', 'Home'],
  ['/register', 'Register'],
  ['/me', 'My deals'],
  ['/deals', 'Deal page'],
] as const;

const usePath = () => useRouterState({ select: (s) => s.location.pathname });

export const Nav = () => {
  const path = usePath().replace(/\/$/, '') || '/';
  return (
    <nav aria-label="Demo pages" className="-mx-1 mb-6 flex flex-wrap items-center gap-1 text-base font-semibold">
      {NAV_LINKS.map(([href, label]) => {
        const here = href === '/' ? path === '/' : path.startsWith(href);
        return (
          <a
            key={href}
            href={href}
            aria-current={here ? 'page' : undefined}
            className={cn(
              'inline-flex min-h-12 items-center rounded-full px-3 focus-visible:outline-2 focus-visible:outline-fg',
              here ? 'bg-primary text-primary-fg' : 'text-primary hover:bg-surface',
            )}
          >
            {label}
          </a>
        );
      })}
    </nav>
  );
};

/**
 * The page frame: nav, a 28 px title, a column of children, the demo label. `action` is the screen's one
 * PrimaryAction; on phones it is pinned to the bottom, so the page leaves room for it.
 */
export const Page = ({
  title,
  children,
  wide,
  action,
  subtitle,
}: {
  title: string;
  children: ReactNode;
  wide?: boolean;
  action?: ReactNode;
  subtitle?: ReactNode;
}) => (
  <main
    className={cn(
      'mx-auto min-h-dvh bg-bg px-4 pt-4 text-base text-fg',
      wide ? 'max-w-6xl' : 'max-w-md',
      action ? 'pb-40 sm:pb-8' : 'pb-8',
    )}
  >
    <Nav />
    <header className="mb-6 flex flex-col gap-2">
      <h1 className="text-[28px] font-bold leading-tight">{title}</h1>
      {subtitle ? <div className="text-base text-muted">{subtitle}</div> : null}
    </header>
    <div className="flex flex-col gap-4">
      {children}
      {action ? <div className="sm:order-first">{action}</div> : null}
    </div>
    <footer className="mt-8">
      <DemoLabel />
    </footer>
  </main>
);

export const Field = ({ label, children }: { label: string; children: ReactNode }) => (
  // biome-ignore lint/a11y/noLabelWithoutControl: the control is passed as children, inside the label
  <label className="flex flex-col gap-2 text-base font-semibold">
    {label}
    {children}
  </label>
);
export const INPUT =
  'min-h-12 rounded-xl border-2 border-line bg-bg px-4 text-base font-normal text-fg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary';

/* ---------- blocks ---------- */

export const Card = ({
  children,
  className,
  label,
  as: Tag = 'section',
}: {
  children: ReactNode;
  className?: string;
  label?: string;
  as?: 'section' | 'div' | 'article' | 'li';
}) => (
  <Tag
    aria-label={label}
    className={cn('flex flex-col gap-4 rounded-2xl border border-soft bg-surface p-4', className)}
  >
    {children}
  </Tag>
);

export type ChipStatus = 'locked' | 'released' | 'failed' | 'pending';
const CHIP: Record<ChipStatus, { cls: string; icon: (c?: string) => ReactNode; label: string }> = {
  locked: { cls: 'bg-warn-bg text-warn', icon: Icon.lock, label: 'Locked' },
  released: { cls: 'bg-pass-bg text-pass', icon: Icon.check, label: 'Released' },
  failed: { cls: 'bg-fail-bg text-fail', icon: Icon.x, label: 'Failed' },
  pending: { cls: 'bg-bg text-muted border border-soft', icon: Icon.clock, label: 'Pending' },
};
export const StatusChip = ({ status, children }: { status: ChipStatus; children?: ReactNode }) => {
  const c = CHIP[status];
  return (
    <span
      data-chip={status}
      className={cn('inline-flex items-center gap-1 rounded-full px-3 py-1 text-sm font-bold', c.cls)}
    >
      {c.icon('size-4')}
      {children ?? c.label}
    </span>
  );
};

/** Names first, IDs second: the name, a small RID chip with a copy button, the full fingerprint in the tooltip. */
export const RidChip = ({
  name,
  rid,
  fingerprint,
  size = 'md',
}: {
  name?: string;
  rid: string;
  fingerprint?: string;
  size?: 'md' | 'lg';
}) => {
  const [copied, setCopied] = useState(false);
  const tip = fingerprint ? `${rid}\nFingerprint ${fingerprint}` : rid;
  return (
    <span className="inline-flex min-w-0 flex-wrap items-center gap-2">
      {name ? <span className={cn('font-bold', size === 'lg' ? 'text-[28px]' : 'text-base')}>{name}</span> : null}
      <span
        title={tip}
        className="inline-flex items-center rounded-md border border-soft bg-bg py-0.5 pr-0.5 pl-2 font-mono text-sm text-muted"
      >
        <span>{shortRid(rid)}</span>
        <button
          type="button"
          aria-label={copied ? 'RID copied' : `Copy RID ${rid}`}
          title={copied ? 'Copied' : 'Copy RID'}
          className="ml-1 inline-flex size-8 items-center justify-center rounded text-muted hover:text-fg focus-visible:outline-2 focus-visible:outline-fg"
          onClick={() => {
            void navigator.clipboard?.writeText(rid).then(
              () => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              },
              () => undefined,
            );
          }}
        >
          {copied ? Icon.check('size-4 text-pass') : Icon.copy('size-4')}
        </button>
      </span>
    </span>
  );
};

const Spinner = () => (
  <svg aria-hidden="true" viewBox="0 0 24 24" className="size-5 motion-safe:animate-spin" fill="none">
    <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.3" strokeWidth="3" />
    <path d="M21 12a9 9 0 00-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
  </svg>
);

/**
 * The screen's one primary action: full width, pinned to the bottom on phones (safe-area aware), a spinner while
 * pending, and a plain-language reason when disabled.
 */
export const PrimaryAction = ({
  children,
  onClick,
  pending = false,
  disabledReason,
  type = 'button',
  form,
}: {
  children: ReactNode;
  onClick?: () => void;
  pending?: boolean;
  disabledReason?: string | undefined;
  type?: 'button' | 'submit';
  form?: string;
}) => {
  const reasonId = useId();
  return (
    <div className="fixed inset-x-0 bottom-0 z-20 border-t border-soft bg-bg/95 px-4 pt-3 pb-[max(1rem,env(safe-area-inset-bottom))] backdrop-blur sm:static sm:border-0 sm:bg-transparent sm:p-0 sm:backdrop-blur-none">
      <div className="mx-auto flex max-w-md flex-col gap-2 sm:max-w-none">
        <Button
          type={type}
          {...(form ? { form } : {})}
          className="min-h-14 w-full rounded-xl text-[20px]"
          disabled={pending || Boolean(disabledReason)}
          aria-busy={pending || undefined}
          aria-describedby={disabledReason ? reasonId : undefined}
          {...(onClick ? { onClick } : {})}
        >
          {pending ? <Spinner /> : null}
          {children}
        </Button>
        {disabledReason ? (
          <p id={reasonId} className="text-center text-sm text-muted">
            {disabledReason}
          </p>
        ) : null}
      </div>
    </div>
  );
};

/** Always say whose turn it is. */
export const TurnBanner = ({ turn, children }: { turn: 'you' | 'wait' | 'auto' | 'done'; children: ReactNode }) => {
  const tone = {
    you: 'border-primary bg-primary text-primary-fg',
    wait: 'border-soft bg-surface text-fg',
    auto: 'border-soft bg-surface text-fg',
    done: 'border-pass bg-pass-bg text-pass',
  }[turn];
  const icon = { you: Icon.hand, wait: Icon.clock, auto: Icon.clock, done: Icon.check }[turn];
  return (
    <div
      role="status"
      data-turn={turn}
      className={cn('flex items-center gap-3 rounded-2xl border-2 px-4 py-3 text-[20px] font-bold', tone)}
    >
      {icon('size-6')}
      <span>{children}</span>
    </div>
  );
};

export const TxLink = ({
  hash,
  explorerBase,
  label,
}: {
  hash: string;
  explorerBase?: string | undefined;
  label?: string;
}) => {
  const short = `${hash.slice(0, 6)}…${hash.slice(-4)}`;
  const text = label ?? `Transaction ${short}`;
  if (!explorerBase)
    return (
      <span title={hash} className="font-mono text-sm text-muted">
        {text}
      </span>
    );
  return (
    <a
      href={`${explorerBase.replace(/\/$/, '')}/transactions/${hash}`}
      target="_blank"
      rel="noreferrer"
      title={hash}
      className="inline-flex items-center gap-1 font-mono text-sm text-primary underline"
    >
      {text}
      {Icon.external('size-4')}
    </a>
  );
};

/* ---------- feedback ---------- */

export interface ToastData {
  tone: 'success' | 'error';
  message: string;
  tx?: { hash: string; explorerBase?: string | undefined };
}

/** A success (green check) or error message, with an optional transaction link. Announced politely. */
export const Toast = ({ toast, onClose }: { toast: ToastData; onClose?: () => void }) => (
  <div
    role={toast.tone === 'error' ? 'alert' : 'status'}
    data-toast={toast.tone}
    className={cn(
      'flex items-start gap-3 rounded-2xl border-2 p-4 shadow-sm',
      toast.tone === 'success' ? 'border-pass bg-pass-bg text-pass' : 'border-fail bg-fail-bg text-fail',
    )}
  >
    {toast.tone === 'success' ? Icon.check('size-6') : Icon.x('size-6')}
    <div className="flex min-w-0 flex-1 flex-col gap-1">
      <p className="text-base font-bold">{toast.message}</p>
      {toast.tx ? <TxLink hash={toast.tx.hash} explorerBase={toast.tx.explorerBase} /> : null}
    </div>
    {onClose ? (
      <button
        type="button"
        aria-label="Dismiss message"
        onClick={onClose}
        className="-m-2 inline-flex size-10 items-center justify-center rounded focus-visible:outline-2 focus-visible:outline-fg"
      >
        {Icon.x('size-4')}
      </button>
    ) : null}
  </div>
);
export const SuccessMessage = ({ children, tx }: { children: string; tx?: ToastData['tx'] }) => (
  <Toast toast={{ tone: 'success', message: children, ...(tx ? { tx } : {}) }} />
);

/** One toast at a time; success toasts clear themselves after `ms`. */
export function useToast(ms = 6000) {
  const [toast, setToast] = useState<ToastData | undefined>();
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const clear = useCallback(() => setToast(undefined), []);
  const show = useCallback(
    (t: ToastData) => {
      clearTimeout(timer.current);
      setToast(t);
      if (t.tone === 'success') timer.current = setTimeout(() => setToast(undefined), ms);
    },
    [ms],
  );
  useEffect(() => () => clearTimeout(timer.current), []);
  return { toast, show, clear };
}

export const Skeleton = ({ lines = 3, className }: { lines?: number; className?: string }) => (
  <div aria-busy="true" className={cn('flex flex-col gap-3 rounded-2xl border border-soft bg-surface p-4', className)}>
    <span className="sr-only">Loading…</span>
    {Array.from({ length: lines }, (_, i) => (
      <span
        // biome-ignore lint/suspicious/noArrayIndexKey: static placeholder rows
        key={i}
        aria-hidden="true"
        className={cn('block h-4 rounded bg-soft motion-safe:animate-pulse', i === 0 ? 'h-6 w-2/3' : 'w-full')}
      />
    ))}
  </div>
);

export const EmptyState = ({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) => (
  <Card className="items-center py-8 text-center">
    <h2 className="text-[20px] font-bold">{title}</h2>
    {children ? <p className="text-base text-muted">{children}</p> : null}
    {action}
  </Card>
);
