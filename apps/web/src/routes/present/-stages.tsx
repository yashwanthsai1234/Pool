// useDealStages: the demo product has no signed live feed, so the deal is polled every 1.5 s until it is released.
// Every dots view (/me, /deals detail, /present) uses this hook; the server stays the truth.
import { useQuery } from '@tanstack/react-query';
import { type Deal, dealKey } from '../../lib/demo-deals.tsx';
import { API_BASE } from '../../lib/paths.ts';

export const POLL_MS = 1500;

/** The server builds the PDF URL without the `/api` prefix the web app is served under. */
export const pdfHref = (url: string) => {
  const path = /^https?:/.test(url) ? new URL(url).pathname : url;
  return path.startsWith(`${API_BASE}/`) ? path : `${API_BASE}${path.startsWith('/') ? '' : '/'}${path}`;
};

export function useDealStages(dealId: string, initial?: Deal) {
  const q = useQuery({
    queryKey: dealKey(dealId),
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/demo/deals/${dealId}`);
      if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
      return (await res.json()) as Deal;
    },
    ...(initial ? { initialData: initial } : {}),
    staleTime: 0,
    refetchInterval: (query) => (query.state.data?.status === 'released' ? false : POLL_MS),
  });
  return { deal: q.data, stages: q.data?.stages, error: q.error };
}
