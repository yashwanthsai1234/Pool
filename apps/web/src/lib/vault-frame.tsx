// The vault frame, shared by the party app and the lawyer console: one hidden iframe on the vault's own origin (4.10),
// the pinned-origin handshake, and the three states a page must show (opening, could not open, does not match the release).
// `frameApiClient` is the one way a page makes signed API calls: the frame signs, the page never holds a key.
// Source: https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-allow; DESIGN.md 6.4 "Code integrity"
import { connectVaultFrame, VAULT_FRAME_ALLOW, type VaultFrame } from '@legx/vault-host/app';
import { type ReactNode, useEffect, useRef, useState } from 'react';
import { type ApiClient, createApiClient } from './api.ts';

type FrameVault = VaultFrame['vault'];

/** An API client whose every request is signed inside the frame. `pairId` omitted: the pair id the frame remembered at enroll. */
export function frameApiClient(
  vault: Pick<FrameVault, 'signApi'>,
  validatedIndex: () => Promise<number>,
  dealId: string,
  pairId?: string,
): ApiClient {
  return createApiClient({
    signRequest: async (req) =>
      vault.signApi({
        dealId,
        ...(pairId === undefined ? {} : { pairId }),
        ...req,
        ledgerIndex: await validatedIndex(),
      }),
  });
}

export function VaultFrameGate({
  role,
  vaultOrigin,
  children,
}: {
  role: 'alice' | 'bob' | 'lawyerA' | 'lawyerB';
  vaultOrigin: string;
  /** Called with the frame once it is ready and matches the published release. */
  children: (frame: VaultFrame & { status: { kind: 'ready' } }) => ReactNode;
}) {
  const ref = useRef<HTMLIFrameElement>(null);
  const [frame, setFrame] = useState<VaultFrame>();
  const [failed, setFailed] = useState<string>();
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    let live = true;
    connectVaultFrame({ frame: el, vaultOrigin, role }).then(
      (f) => live && setFrame(f),
      (e: { code?: string }) => live && setFailed(e.code ?? 'VAULT_FRAME'),
    );
    return () => {
      live = false;
    };
  }, [vaultOrigin, role]);
  return (
    <>
      <iframe
        ref={ref}
        title="Key vault"
        src={vaultOrigin}
        allow={VAULT_FRAME_ALLOW}
        hidden
        referrerPolicy="no-referrer"
      />
      {failed ? (
        <p role="alert" className="p-4">
          The key vault could not be opened ({failed}). Nothing was signed.
        </p>
      ) : frame?.status.kind === 'ready' ? (
        children(frame as VaultFrame & { status: { kind: 'ready' } })
      ) : frame ? (
        <p role="alert" className="p-4">
          The key vault does not match the published release. Nothing was signed.
        </p>
      ) : (
        <p className="p-4">Opening the key vault</p>
      )}
    </>
  );
}
