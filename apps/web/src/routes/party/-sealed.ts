// The deal as the phone verified it: the public data, the seal recomputed from it, and the coordinator's deal view.
// Every screen that leads to a signature reads this and refuses on a seal mismatch.
import { useQuery } from '@tanstack/react-query';
import { fetchSealedDeal } from '../../lib/seal.ts';
import { usePartyStrict } from './-context.tsx';

export function useSealedDeal() {
  const s = usePartyStrict();
  return useQuery({
    queryKey: ['party', s.dealId, 'sealed'],
    queryFn: () => fetchSealedDeal(s.api, s.dealId),
  });
}
