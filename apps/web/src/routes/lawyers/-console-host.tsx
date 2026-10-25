// Boots one lawyer half of the console in production (I-W-10): `?deal=<deal id>&role=LA|LB`. The vault frame of that half's own
// namespace holds the keys; the console is composed from the validated snapshot, the frame and the public XRPL node
// (`createConsoleDeps`), the same way the party app is composed (`PartyHost`).
// Source: DESIGN.md 4.4; build/DECISIONS.md OD-35
import { enrollmentKeys } from '@legx/vault';
import { webauthnApproval } from '@legx/vault/frost/approval';
import { useQuery } from '@tanstack/react-query';
import { API_BASE } from '../../lib/paths.ts';
import { frameApiClient, VaultFrameGate } from '../../lib/vault-frame.tsx';
import { xrplRpc } from '../../lib/xrpl-rpc.ts';
import { chipRelay } from './-console/chipRelay.ts';
import { rpcPublicLedger } from './-console/compose.ts';
import { createLawyerConsole } from './-console/index.ts';
import type { Role } from './-console/ports.ts';
import { createApprovalPrompt } from './-console/prompt.ts';
import { createConsoleDeps, ReleaseProofs } from './-console/services.ts';
import { type ConsoleWiring, LawyerConsolePage } from './-console/ui.tsx';
import { LAWYER_OPS_DB } from './-console/vaults.ts';

type Frame = Parameters<Parameters<typeof VaultFrameGate>[0]['children']>[0];

function Half({ frame, dealId, role, rpcUrl }: { frame: Frame; dealId: string; role: Role; rpcUrl: string }) {
  const half = useQuery({
    queryKey: ['lawyer', 'console', dealId, role],
    staleTime: Number.POSITIVE_INFINITY,
    retry: false,
    queryFn: async (): Promise<ConsoleWiring> => {
      const rpc = xrplRpc(rpcUrl);
      const prompt = createApprovalPrompt();
      const deps = await createConsoleDeps({
        dealId,
        role,
        api: frameApiClient(frame.vault, rpc.validatedIndex, dealId),
        vault: frame.vault,
        opsStore: enrollmentKeys({ role: role === 'LA' ? 'lawyerA' : 'lawyerB', dbName: LAWYER_OPS_DB[role] }),
        publicLedger: rpcPublicLedger(rpcUrl),
        confirm: prompt.confirm,
        // No credential id is kept: the browser offers this lawyer's discoverable credentials for this site, and the firm HSM
        // checks the assertion against the registered key.
        requestApproval: webauthnApproval(location.hostname),
        // The clauses and salts are given to the lawyer out of band; no route serves them, so the contract card refuses
        // (ROOT_MISMATCH) until they are loaded.
        contract: { clauses: [], salts: [] },
        proofs: new ReleaseProofs(),
      });
      return { [role]: { console: createLawyerConsole(deps), prompt, chip: { relay: chipRelay(API_BASE) } } };
    },
  });
  if (half.isError)
    return (
      <p role="alert" className="p-4">
        The console could not be opened for this deal. Nothing was signed.
      </p>
    );
  return half.data ? <LawyerConsolePage wiring={half.data} /> : <p className="p-4">Opening your console</p>;
}

export function LawyerConsoleHost({
  dealId,
  role,
  vaultOrigin,
  rpcUrl,
}: {
  dealId: string;
  role: Role;
  vaultOrigin: string;
  rpcUrl: string;
}) {
  return (
    <VaultFrameGate role={role === 'LA' ? 'lawyerA' : 'lawyerB'} vaultOrigin={vaultOrigin}>
      {(frame) => <Half frame={frame} dealId={dealId} role={role} rpcUrl={rpcUrl} />}
    </VaultFrameGate>
  );
}
