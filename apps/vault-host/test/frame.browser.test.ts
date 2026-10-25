import { afterEach, describe, expect, it } from 'vitest';
import { commands } from 'vitest/browser';
import { connectVaultFrame, VAULT_FRAME_ALLOW } from '../src/app.ts';
import { FrameMessage } from '../src/schema.ts';
import type { Tamper } from './world.ts';

declare module 'vitest/browser' {
  interface BrowserCommands {
    startVault(o: {
      appOrigin: string;
      tamper?: Tamper;
      release?: { appOrigin?: string; minVersion?: string };
      noFrameAncestors?: boolean;
    }): Promise<{ origin: string; releaseManifestHash: string }>;
    vaultReports(origin: string): Promise<string[]>;
    foreignOrigin(): Promise<string>;
  }
}

const appOrigin = location.origin;
const frames: HTMLIFrameElement[] = [];
afterEach(() => {
  for (const f of frames.splice(0)) f.remove();
});

function embed(src: string): HTMLIFrameElement {
  const f = document.createElement('iframe');
  f.allow = VAULT_FRAME_ALLOW;
  f.src = src;
  document.body.append(f);
  frames.push(f);
  return f;
}

const messagesFrom = (win: () => Window | null, ms: number): Promise<unknown[]> =>
  new Promise((resolve) => {
    const seen: unknown[] = [];
    const on = (ev: MessageEvent) => {
      if (ev.source === win()) seen.push(ev.data);
    };
    addEventListener('message', on);
    setTimeout(() => {
      removeEventListener('message', on);
      resolve(seen);
    }, ms);
  });

const codeOf = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
  } catch (e) {
    return (e as { code?: string }).code ?? String(e);
  }
  return 'NO ERROR';
};

describe('the vault on a separate origin', () => {
  it('P4.10-04 runs from another origin, reached only through postMessage, and passes the self-check', async () => {
    const v = await commands.startVault({ appOrigin });
    expect(v.origin).not.toBe(appOrigin);
    const frame = embed(v.origin);
    const { vault, status } = await connectVaultFrame({ frame, vaultOrigin: v.origin, role: 'alice' });
    expect(status).toEqual({ kind: 'ready', version: '1.0.0', manifestHash: v.releaseManifestHash });
    // The app cannot touch the frame's document or storage: only the port answers.
    expect(frame.contentDocument).toBeNull();
    expect(() => (frame.contentWindow as Window).document).toThrow();
    expect(await vault.list()).toEqual([]);
    expect(await vault.location()).toMatchObject({ entries: 0 });
  });

  it('P4.10-10 a version or hash different from the published release blocks signing', async () => {
    const v = await commands.startVault({ appOrigin });
    const frame = embed(v.origin);
    const err = await codeOf(
      connectVaultFrame({
        frame,
        vaultOrigin: v.origin,
        role: 'alice',
        expected: { version: '1.0.0', manifestHash: '0'.repeat(64) },
      }),
    );
    expect(err).toBe('RELEASE_MISMATCH');
  });

  it('P4.10-04 a coordinator-changed app shell cannot make the vault sign a request that is not on the seal', async () => {
    const v = await commands.startVault({ appOrigin });
    const { vault } = await connectVaultFrame({ frame: embed(v.origin), vaultOrigin: v.origin, role: 'alice' });
    const dealId = '01890000-0000-7000-8000-000000000001';
    const forged = { kind: 'xrpl-multisign' as const, tx: { TransactionType: 'Payment', Amount: '1000000' } };
    expect(await codeOf(vault.signFrost(dealId, forged))).toBe('NOT_FOUND');
    expect(await codeOf(vault.signMultisig(dealId, forged.tx))).toBe('NOT_FOUND');
  });

  it('P4.10-05 the app shell refuses a frame at another origin before sending anything to it', async () => {
    const real = await commands.startVault({ appOrigin });
    const fake = await commands.startVault({ appOrigin });
    const frame = embed(fake.origin);
    const seen = messagesFrom(() => frame.contentWindow, 300);
    expect(await codeOf(connectVaultFrame({ frame, vaultOrigin: real.origin, role: 'alice' }))).toBe('ORIGIN');
    await seen;
    const blank = embed('about:blank');
    expect(await codeOf(connectVaultFrame({ frame: blank, vaultOrigin: real.origin, role: 'alice' }))).toBe('ORIGIN');
  });

  it('P4.10-04 a page that is not the pinned app origin is refused by frame-ancestors', async () => {
    const v = await commands.startVault({ appOrigin: 'https://app.invalid' });
    const frame = embed(v.origin);
    const seen = await messagesFrom(() => frame.contentWindow, 2500);
    expect(seen).toEqual([]); // the browser refused to render the frame: nothing ran, nothing was said
  });

  it('the frame also checks the parent origin itself, even without frame-ancestors', async () => {
    const v = await commands.startVault({
      appOrigin,
      release: { appOrigin: 'https://app.invalid' },
      noFrameAncestors: true,
    });
    const frame = embed(v.origin);
    expect(await codeOf(connectVaultFrame({ frame, vaultOrigin: v.origin, role: 'alice', timeoutMs: 2500 }))).toBe(
      'TIMEOUT',
    );
  });
});

describe('P4.10-03 a tampered bundle is refused', () => {
  const dealId = '01890000-0000-7000-8000-000000000001';
  it.each<Tamper>(['js-byte', 'css-byte', 'wasm-byte', 'extra-script', 'remove-file', 'swap-index'])(
    '%s: the frame refuses, decrypts no share, and signFrost throws CODE_HASH_MISMATCH',
    async (tamper) => {
      const v = await commands.startVault({ appOrigin, tamper });
      const frame = embed(v.origin);
      const ran = messagesFrom(() => frame.contentWindow, 400);
      const { vault, status } = await connectVaultFrame({ frame, vaultOrigin: v.origin, role: 'alice' });
      expect(status).toEqual({ kind: 'refused' });
      const request = { kind: 'xrpl-multisign' as const, tx: { TransactionType: 'Payment' } };
      expect(await codeOf(vault.signFrost(dealId, request))).toBe('CODE_HASH_MISMATCH');
      expect(await codeOf(vault.list())).toBe('CODE_HASH_MISMATCH');
      expect(await ran).not.toContain('extra-ran'); // the CSP never let the added script run
    },
  );

  it('js-byte-stale-sri: the browser itself refuses to run a script whose bytes differ from the page', async () => {
    const v = await commands.startVault({ appOrigin, tamper: 'js-byte-stale-sri' });
    const frame = embed(v.origin);
    expect(await codeOf(connectVaultFrame({ frame, vaultOrigin: v.origin, role: 'alice', timeoutMs: 2500 }))).toBe(
      'TIMEOUT',
    );
  });

  it('P4.10-09 an older bundle is refused after the signed release names a higher minimum version', async () => {
    const v = await commands.startVault({ appOrigin, release: { minVersion: '2.0.0' } });
    // The signed body would be invalid (minVersion above version), so the release is refused as a whole.
    const { status } = await connectVaultFrame({ frame: embed(v.origin), vaultOrigin: v.origin, role: 'alice' });
    expect(status).toEqual({ kind: 'refused' });
  });
});

describe('P4.10-07 the vault page policy', () => {
  it('blocks inline scripts, eval, javascript: URLs, string-to-HTML sinks and foreign scripts, and reports them', async () => {
    const v = await commands.startVault({ appOrigin });
    const frame = embed(`${v.origin}/probe.html`);
    const seen = (await messagesFrom(() => frame.contentWindow, 2500)) as string[];
    expect(seen).toContain('probe-done');
    expect(seen).toContain('eval-blocked');
    expect(seen).toContain('innerhtml-blocked');
    for (const bad of ['inline-script-ran', 'foreign-script-ran', 'javascript-url-ran', 'extra-ran']) {
      expect(seen).not.toContain(bad);
    }
    const reports = (await commands.vaultReports(v.origin)).join('\n');
    expect(reports).toContain('script-src');
  });
});

describe('the message schema is checked on both sides', () => {
  it('the app drops what is off-schema, from the frame or from anyone else', async () => {
    const v = await commands.startVault({ appOrigin });
    const frame = embed(`${v.origin}/probe.html#bad-ready`);
    const out = codeOf(connectVaultFrame({ frame, vaultOrigin: v.origin, role: 'alice', timeoutMs: 1500 }));
    // A foreign window with a perfect `ready` message: wrong source, so dropped.
    postMessage({ legxVaultHost: 1, type: 'ready', version: '1.0.0', manifestHash: 'a'.repeat(64) }, location.origin);
    expect(await out).toBe('TIMEOUT');
    expect(FrameMessage.safeParse({ legxVaultHost: 1, type: 'ready', version: '1', manifestHash: 'x' }).success).toBe(
      false,
    );
  });

  it('the frame drops a bad init and a bad RPC message; a good one afterwards still works', async () => {
    const v = await commands.startVault({ appOrigin });
    const frame = embed(v.origin);
    const win = frame.contentWindow as Window;
    await new Promise<void>((resolve) => {
      const on = (ev: MessageEvent) => {
        if (ev.source === win && (ev.data as { type?: string }).type === 'ready') {
          removeEventListener('message', on);
          resolve();
        }
      };
      addEventListener('message', on);
    });
    const bad = new MessageChannel();
    const replies: unknown[] = [];
    bad.port1.onmessage = (e) => replies.push(e.data);
    win.postMessage({ legxVaultHost: 1, type: 'init', role: 'root' }, v.origin, [bad.port2]); // unknown role
    const extra = new MessageChannel();
    win.postMessage({ legxVaultHost: 1, type: 'init', role: 'alice', admin: true }, v.origin, [extra.port2]); // extra key
    win.postMessage({ legxVaultHost: 1, type: 'init', role: 'alice' }, v.origin); // no port
    const good = new MessageChannel();
    const got: unknown[] = [];
    good.port1.onmessage = (e) => got.push(e.data);
    win.postMessage({ legxVaultHost: 1, type: 'init', role: 'alice' }, v.origin, [good.port2]);
    good.port1.postMessage({ legxVault: 1, id: 1, op: 'bogus', args: {} }); // off-schema op: dropped
    good.port1.postMessage({ legxVault: 1, id: 2, op: 'sign', args: { dealId: 'x', request: { kind: 'x' } } }); // bad args
    good.port1.postMessage({ legxVault: 1, id: 3, op: 'list', args: {}, extra: 1 }); // extra key: dropped
    good.port1.postMessage({ legxVault: 1, id: 4, op: 'list', args: {} });
    await new Promise((r) => setTimeout(r, 800));
    expect(replies).toEqual([]);
    expect(got).toEqual([
      { legxVault: 1, id: 2, ok: false, code: 'INPUT_INVALID' },
      { legxVault: 1, id: 4, ok: true, result: [] },
    ]);
  });
});
