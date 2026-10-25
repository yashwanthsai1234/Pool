// Boots the real party services in production (I-31): `?deal=<deal id>&key=<your enrollment key pair id>` names the deal and the
// key the lawyer pinned for this phone. The vault runs in its own origin's iframe (`VITE_VAULT_ORIGIN`, 4.10): it signs every
// API request and every share operation, so this page never holds a key. Without that configuration the host renders its
// children with no provider, and the party screens show "no deal yet".
// Source: https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-allow; DESIGN.md 6.4 "Code integrity"
import { type ReactNode, useMemo } from 'react';
import { frameApiClient, VaultFrameGate } from '../../lib/vault-frame.tsx';
import { xrplRpc } from '../../lib/xrpl-rpc.ts';
import { PartyProvider, type PartyServices } from './-context.tsx';
import { createPartyServices } from './-services.ts';

type Env = Readonly<Record<string, string | boolean | undefined>>;
const str = (v: unknown) => (typeof v === 'string' && v !== '' ? v : undefined);

export function PartyHost({
  role,
  search,
  env,
  children,
}: {
  role: 'alice' | 'bob';
  search: string;
  env: Env;
  children: ReactNode;
}) {
  const params = new URLSearchParams(search);
  const [dealId, pairId] = [str(params.get('deal')), str(params.get('key'))];
  const vaultOrigin = str(env.VITE_VAULT_ORIGIN);
  const rpcUrl = str(env.VITE_LEGX_XRPL_RPC);
  if (!dealId || !pairId || !vaultOrigin || !rpcUrl) return <>{children}</>;
  return (
    <VaultFrameGate role={role} vaultOrigin={vaultOrigin}>
      {(frame) => (
        <Ready frame={frame} role={role} dealId={dealId} pairId={pairId} rpcUrl={rpcUrl}>
          {children}
        </Ready>
      )}
    </VaultFrameGate>
  );
}

/** The services are made once per frame: the registry and ledger caches live in them. */
function Ready(p: {
  frame: Parameters<Parameters<typeof VaultFrameGate>[0]['children']>[0];
  role: 'alice' | 'bob';
  dealId: string;
  pairId: string;
  rpcUrl: string;
  children: ReactNode;
}) {
  const services = useMemo<PartyServices>(() => {
    const rpc = xrplRpc(p.rpcUrl);
    let closeTime = 0;
    void rpc.latest().then((l) => {
      closeTime = l.closeTime;
    });
    return createPartyServices({
      dealId: p.dealId,
      role: p.role,
      api: frameApiClient(p.frame.vault, rpc.validatedIndex, p.dealId, p.pairId),
      vault: p.frame.vault,
      closeTime: () => closeTime,
      txLedgerIndex: rpc.txLedgerIndex,
      validatedIndex: rpc.validatedIndex,
    });
  }, [p.frame, p.role, p.dealId, p.pairId, p.rpcUrl]);
  return <PartyProvider value={services}>{p.children}</PartyProvider>;
}
