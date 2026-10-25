// The vault frame (DESIGN 6.4 "Code integrity"): a page on its own origin that the app embeds in an iframe and
// reaches only through `postMessage`. Order of events: self-check against the signed release; only if it passes,
// announce `ready` to the pinned app origin; accept one `init` (checked against the schema, the origin and the
// source) with a MessagePort; serve the vault on that port. On a mismatch nothing of the vault is created, and every
// request on the port is answered with CODE_HASH_MISMATCH.
// Source: https://html.spec.whatwg.org/multipage/web-messaging.html#dom-window-postmessage-options
import './style.css';
import { createVault, serveVault, type VaultCode, vaultFrameHost } from '@legx/vault';
import { CodeMismatch, selfCheck } from './check.ts';
import { FrameMessage, InitMessage } from './schema.ts';

const $ = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

function show(text: string, refused: boolean): void {
  const state = $('state');
  state.textContent = text;
  state.className = refused ? 'refused' : '';
}

function showFacts(version: string, hash: string): void {
  $('origin').textContent = location.origin;
  $('version').textContent = version;
  $('hash').textContent = hash;
  for (const id of ['facts', 'limit']) $(id).hidden = false;
}

const tell = (target: string, m: FrameMessage): void => window.parent.postMessage(FrameMessage.parse(m), target);

/** Answers every well-formed request with CODE_HASH_MISMATCH. The vault does not exist in this state. */
function refuseAll(port: MessagePort): void {
  port.onmessage = (ev: MessageEvent) => {
    const id = (ev.data as { id?: unknown } | null)?.id;
    if (Number.isInteger(id))
      port.postMessage({ legxVault: 1, id, ok: false, code: 'CODE_HASH_MISMATCH' satisfies VaultCode });
  };
}

/** One `init` from the parent window at `origin`, once. */
function onceInit(origin: string | undefined, accept: (init: InitMessage, port: MessagePort, from: string) => void) {
  const listener = (ev: MessageEvent) => {
    if (ev.source !== window.parent || (origin !== undefined && ev.origin !== origin)) return;
    const init = InitMessage.safeParse(ev.data);
    const [port] = ev.ports;
    if (!init.success || ev.ports.length !== 1 || !port) return; // dropped, never answered
    removeEventListener('message', listener);
    accept(init.data, port, ev.origin);
  };
  addEventListener('message', listener);
}

async function main(): Promise<void> {
  try {
    const release = await selfCheck({
      releaseUrl: __RELEASE_URL__,
      keys: __RELEASE_KEYS__,
      version: __VAULT_VERSION__,
    });
    showFacts(__VAULT_VERSION__, release.manifestHash);
    show('Code matches the published release.', false);
    onceInit(release.appOrigin, (init, port) => {
      // The frame's own host: enrollment keys, API signing, and the seal it verifies itself (OD-36: pinned at join time).
      const host = vaultFrameHost({ role: init.role });
      serveVault(port, createVault({ role: init.role, deals: host.sealedDeal }), host);
    });
    tell(release.appOrigin, {
      legxVaultHost: 1,
      type: 'ready',
      version: __VAULT_VERSION__,
      manifestHash: release.manifestHash,
    });
  } catch (err) {
    if (!(err instanceof CodeMismatch)) throw err;
    show('Code does not match the published release', true);
    onceInit(undefined, (_init, port, from) => {
      refuseAll(port);
      tell(from, { legxVaultHost: 1, type: 'refused', code: 'CODE_HASH_MISMATCH' });
    });
    tell('*', { legxVaultHost: 1, type: 'refused', code: 'CODE_HASH_MISMATCH' });
  }
}

void main();
