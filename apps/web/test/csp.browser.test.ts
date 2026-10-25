import { describe, expect, it } from 'vitest';
import { CSP, CSP_META, withConnectSrc } from '../csp.ts';

// Loads a document that carries the production CSP in a <meta> tag, inside a same-origin srcdoc iframe.
function sandbox(body: string, csp = CSP_META): Promise<{ window: Window & { ran?: boolean } }> {
  return new Promise((resolve) => {
    const frame = document.createElement('iframe');
    document.body.append(frame);
    frame.addEventListener('load', () => resolve({ window: frame.contentWindow as Window & { ran?: boolean } }));
    frame.srcdoc = `<!doctype html><meta http-equiv="Content-Security-Policy" content="${csp}"><body>${body}`;
  });
}

describe('CSP and Trusted Types', () => {
  it('requires the strict directives', () => {
    for (const d of ["script-src 'self'", "object-src 'none'", "base-uri 'none'", "require-trusted-types-for 'script'"])
      expect(CSP).toContain(d);
    expect(CSP).not.toContain('unsafe-inline');
    expect(CSP).not.toContain('unsafe-eval');
  });

  it('blocks an inline script', async () => {
    const { window } = await sandbox('<script>window.ran = true</script>');
    expect(window.ran).toBeUndefined();
  });

  it('control: the same inline script runs under a permissive policy', async () => {
    const { window } = await sandbox('<script>window.ran = true</script>', "script-src 'unsafe-inline'");
    expect(window.ran).toBe(true);
  });

  it('blocks an inline event handler', async () => {
    const { window } = await sandbox('<img src="data:," onerror="window.ran = true">');
    await new Promise((r) => setTimeout(r, 100));
    expect(window.ran).toBeUndefined();
  });

  it('blocks eval', async () => {
    const { window } = await sandbox('');
    expect(() => (window as unknown as { eval: (s: string) => unknown }).eval('1+1')).toThrow();
  });

  it('rejects a string assigned to innerHTML (Trusted Types)', async (ctx) => {
    const { window } = await sandbox('<div id="d"></div>');
    if (!('trustedTypes' in window)) ctx.skip();
    const d = window.document.getElementById('d') as HTMLElement;
    expect(() => {
      d.innerHTML = '<img src=x>';
    }).toThrow(/Trusted/); // a cross-realm TypeError, so match the message
  });
});

describe('framing (I-S-A2)', () => {
  it('the header policy forbids framing and the meta policy omits the ignored directive', () => {
    expect(CSP).toContain("frame-ancestors 'none'");
    expect(CSP_META).not.toContain('frame-ancestors');
  });
});

describe('build-time connect-src (OD-10)', () => {
  it('adds only plain origins and keeps every other directive', () => {
    const w = withConnectSrc(['https://s.altnet.rippletest.net:51234/path']);
    expect(w.CSP).toContain("connect-src 'self' https://s.altnet.rippletest.net:51234;");
    expect(w.CSP).toContain("frame-ancestors 'none'");
    expect(w.CSP_META).not.toContain('frame-ancestors');
    expect(() => withConnectSrc(['https://*.example.com'])).toThrow();
    expect(() => withConnectSrc(['not a url'])).toThrow();
  });
});
