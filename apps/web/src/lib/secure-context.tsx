import type { ReactNode } from 'react';

// Source: https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle ("available only in secure contexts")
// A phone opening http://192.168.x.x gets `crypto.subtle === undefined`; nothing key-related can work there.
export function hasSubtleCrypto(): boolean {
  return typeof globalThis.crypto?.subtle?.digest === 'function';
}

export function SecureContextGate({
  check = hasSubtleCrypto,
  children,
}: {
  check?: () => boolean;
  children: ReactNode;
}) {
  if (check()) return <>{children}</>;
  return (
    <main
      role="alert"
      className="flex min-h-dvh flex-col items-center justify-center gap-4 bg-bg p-8 text-center text-fg"
    >
      <h1 className="text-4xl font-bold">Open the HTTPS link</h1>
      <p className="max-w-md text-lg text-muted">
        This page was opened over plain HTTP, so your browser disables the cryptography it needs. Scan the QR code again
        or open the link that starts with https://.
      </p>
    </main>
  );
}
