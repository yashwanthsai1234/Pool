// Small screens for the 4.3 and 4.4 routes: the QR code with its deep link, and the request panel with one text per
// state. The screens never say "chip verified": ZKPassport proves passive authentication only (DESIGN 10.1).
// Source: https://github.com/kazuhikoarase/qrcode-generator (createSvgTag-free: modules are drawn as React rects)
import type { IdentityPolicy } from '@legx/contracts/values';
import { Button } from '@legx/ui';
import qrcode from 'qrcode-generator';
import { useEffect, useMemo } from 'react';
import type { z } from 'zod';
import { useZkFlow, type ZkState } from './flow.ts';
import type { ZkRequest } from './request.ts';

const QUIET_ZONE = 4;

/** The URL as an SVG QR code (no data: URI, so the strict CSP holds). The text is also the label for screen readers. */
export function QrCode({ value }: { value: string }) {
  const cells = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(value, 'Byte');
    qr.make();
    const n = qr.getModuleCount();
    const dark: [number, number][] = [];
    for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (qr.isDark(y, x)) dark.push([x, y]);
    return { n, dark };
  }, [value]);
  const size = cells.n + 2 * QUIET_ZONE;
  return (
    <svg
      role="img"
      aria-label="QR code for the ZKPassport request"
      data-testid="zk-qr"
      viewBox={`0 0 ${size} ${size}`}
      shapeRendering="crispEdges"
      className="h-auto w-full max-w-[280px] rounded bg-white"
    >
      <rect width={size} height={size} fill="#fff" />
      {cells.dark.map(([x, y]) => (
        <rect key={`${x}-${y}`} x={x + QUIET_ZONE} y={y + QUIET_ZONE} width={1} height={1} fill="#000" />
      ))}
    </svg>
  );
}

const urlOf = (s: ZkState) => ('url' in s ? s.url : undefined);

export interface PassportProofProps {
  /** Builds the request on demand (it can refuse, for example a stale ledger anchor). */
  readonly build: () => Promise<ZkRequest>;
  readonly onDone: (outcome: Extract<ZkState, { step: 'done' }>['outcome']) => void;
  readonly identityPolicy: z.infer<typeof IdentityPolicy>;
  /** Starts the chip path of task 4.6. */
  readonly onUseChip?: () => void;
  readonly timeoutMs?: number;
}

/** The party's passport step: start, QR and link, a text per state, "Try again" after reject, error or timeout. */
export function PassportProof({ build, onDone, identityPolicy, onUseChip, timeoutMs }: PassportProofProps) {
  const { state, start, text } = useZkFlow(timeoutMs);
  const url = urlOf(state);
  useEffect(() => {
    if (state.step === 'done') onDone(state.outcome);
  }, [state, onDone]);
  if (identityPolicy === 'chip') return null; // the zero-knowledge screen is hidden for a chip-only deal
  const retry = ['rejected', 'timeout', 'error'].includes(state.step);
  return (
    <section aria-label="Passport proof" className="flex flex-col gap-3 p-4">
      <p role="status" data-testid="zk-status">
        {text}
        {state.step === 'error' ? ` (${state.message})` : ''}
      </p>
      {url && state.step !== 'done' && (
        <>
          <QrCode value={url} />
          <a className="break-all underline" href={url} data-testid="zk-link">
            Open in the ZKPassport app
          </a>
        </>
      )}
      {(state.step === 'idle' || retry) && (
        <Button onClick={() => void start(build)}>{retry ? 'Try again' : 'Start passport proof'}</Button>
      )}
      {identityPolicy === 'zk-or-chip' && onUseChip && state.step !== 'done' && (
        <Button onClick={onUseChip}>Use my passport chip instead</Button>
      )}
    </section>
  );
}
