import { describe, expect, it } from 'vitest';
import { page } from 'vitest/browser';
import { render } from 'vitest-browser-react';
import { hasSubtleCrypto, SecureContextGate } from '../src/lib/secure-context.tsx';

describe('insecure-context screen (P4.1-05)', () => {
  it('shows a full-screen "Open the HTTPS link" and no app when crypto.subtle is missing', async () => {
    await render(
      <SecureContextGate check={() => false}>
        <p>the app</p>
      </SecureContextGate>,
    );
    await expect.element(page.getByRole('heading', { name: 'Open the HTTPS link' })).toBeVisible();
    await expect.element(page.getByText('the app')).not.toBeInTheDocument();
  });

  it('renders the app in a secure context', async () => {
    expect(hasSubtleCrypto()).toBe(true); // vitest serves from localhost, a secure context
    await render(
      <SecureContextGate>
        <p>the app</p>
      </SecureContextGate>,
    );
    await expect.element(page.getByText('the app')).toBeVisible();
  });

  it('detects the missing API exactly as an insecure origin presents it', () => {
    const real = Object.getOwnPropertyDescriptor(Crypto.prototype, 'subtle');
    Object.defineProperty(Crypto.prototype, 'subtle', { configurable: true, get: () => undefined });
    try {
      expect(hasSubtleCrypto()).toBe(false);
    } finally {
      if (real) Object.defineProperty(Crypto.prototype, 'subtle', real);
    }
  });
});
