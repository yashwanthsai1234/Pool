// Boots the lawyer's deal list in production (I-W-10): the vault frame of the lawyer's own namespace (`?role=LA` or `LB`, default
// LA), the phone-independent public XRPL node for the signed requests' ledger index (OD-10), and `listLawyerDeals`.
import { useQuery } from '@tanstack/react-query';
import { frameApiClient, VaultFrameGate } from '../../lib/vault-frame.tsx';
import { xrplRpc } from '../../lib/xrpl-rpc.ts';
import { LawyerDeals, listLawyerDeals } from './-deals.tsx';

type Frame = Parameters<Parameters<typeof VaultFrameGate>[0]['children']>[0];

function Listed({ frame, rpcUrl }: { frame: Frame; rpcUrl: string }) {
  const rows = useQuery({
    queryKey: ['lawyer', 'deals'],
    queryFn: () => {
      const rpc = xrplRpc(rpcUrl);
      return listLawyerDeals(frame.vault, (dealId) => frameApiClient(frame.vault, rpc.validatedIndex, dealId));
    },
  });
  if (rows.isError)
    return (
      <p role="alert" className="p-4">
        Your deals could not be listed. Nothing was signed.
      </p>
    );
  return rows.data ? <LawyerDeals rows={rows.data} /> : <p className="p-4">Loading your deals</p>;
}

export function LawyerDealsHost({
  search,
  vaultOrigin,
  rpcUrl,
}: {
  search: string;
  vaultOrigin: string;
  rpcUrl: string;
}) {
  const role = new URLSearchParams(search).get('role') === 'LB' ? 'lawyerB' : 'lawyerA';
  return (
    <VaultFrameGate role={role} vaultOrigin={vaultOrigin}>
      {(frame) => <Listed frame={frame} rpcUrl={rpcUrl} />}
    </VaultFrameGate>
  );
}
