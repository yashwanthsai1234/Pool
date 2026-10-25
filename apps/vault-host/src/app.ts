// The app side of the frame (the web app and the lawyer console import this): the vault origin is pinned, the
// frame is reached only through `postMessage`, every message is checked against the schema, and the vault RPC runs
// on a private MessagePort. A frame at another origin is refused before anything is sent to it (P4.10-05).
// Source: https://html.spec.whatwg.org/multipage/web-messaging.html#message-channels
import { connectVault } from '@legx/vault';
import { FrameMessage, type InitMessage } from './schema.ts';

export type FrameErrorCode = 'ORIGIN' | 'TIMEOUT' | 'RELEASE_MISMATCH';
export class VaultFrameError extends Error {
  readonly code: FrameErrorCode;
  constructor(code: FrameErrorCode) {
    super(code);
    this.name = 'VaultFrameError';
    this.code = code;
  }
}

export interface FrameOptions {
  frame: HTMLIFrameElement;
  /** The one origin the app will talk to, pinned at build time. */
  vaultOrigin: string;
  role: InitMessage['role'];
  /** What the app read from the published release.json: a different version or hash blocks signing (P4.10-10). */
  expected?: { version: string; manifestHash: string };
  timeoutMs?: number;
}

export interface VaultFrame {
  vault: ReturnType<typeof connectVault>;
  /** What the frame says it runs. `refused` means the frame found its own code wrong: every call then fails. */
  status: { kind: 'ready'; version: string; manifestHash: string } | { kind: 'refused' };
}

/** The attribute value for `allow` on the iframe: WebAuthn (PRF) inside the vault origin (task 4.2 request). */
export const VAULT_FRAME_ALLOW = 'publickey-credentials-get; publickey-credentials-create';

export function connectVaultFrame(o: FrameOptions): Promise<VaultFrame> {
  const { frame } = o;
  if (!frame.src || new URL(frame.src, location.href).origin !== o.vaultOrigin) {
    return Promise.reject(new VaultFrameError('ORIGIN'));
  }
  return new Promise((resolve, reject) => {
    const done = (fn: () => void) => {
      removeEventListener('message', listener);
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(() => done(() => reject(new VaultFrameError('TIMEOUT'))), o.timeoutMs ?? 20_000);
    const listener = (ev: MessageEvent) => {
      if (ev.source !== frame.contentWindow || ev.origin !== o.vaultOrigin) return; // not the pinned frame
      const msg = FrameMessage.safeParse(ev.data);
      if (!msg.success) return; // off-schema: dropped
      const m = msg.data;
      if (
        m.type === 'ready' &&
        o.expected &&
        (m.version !== o.expected.version || m.manifestHash !== o.expected.manifestHash)
      ) {
        return done(() => reject(new VaultFrameError('RELEASE_MISMATCH')));
      }
      const { port1, port2 } = new MessageChannel();
      const init: InitMessage = { legxVaultHost: 1, type: 'init', role: o.role };
      frame.contentWindow?.postMessage(init, o.vaultOrigin, [port2]);
      const status: VaultFrame['status'] =
        m.type === 'ready' ? { kind: 'ready', version: m.version, manifestHash: m.manifestHash } : { kind: 'refused' };
      done(() => resolve({ vault: connectVault(port1), status }));
    };
    addEventListener('message', listener);
  });
}
