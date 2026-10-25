// Client of the demo product API (build/PRODUCT_DEMO.md sections 1 to 4) and the live progress artifact.
// The feed row of a step carries no state we rely on: any `walkthrough.step` row for the deal refetches its detail.

import { DealProgress } from '@legx/ui';
import { skipToken, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { type LiveRows, liveRowsKey, useLiveDeal } from './live.ts';
import { API_BASE } from './paths.ts';

export interface Participant {
  rid: string;
  name: string;
  fingerprint: string;
  xrplAddress: string;
}
export interface Who {
  rid: string;
  name: string;
  at?: string;
  signatureFingerprint?: string;
}
export interface Stage {
  n: number;
  name: string;
  actor: 'sender' | 'recipient' | 'auto';
  status: 'pending' | 'done' | 'failed';
  at?: string;
  by?: string;
  txHashes: string[];
}
interface Tally {
  done: number;
  of: number;
  by: Who[];
}
export interface Deal {
  id: string;
  dealId: string;
  createdAt: string;
  status: 'locked' | 'released';
  sender: Participant;
  recipient: Participant;
  amountXrp: number;
  terms: string;
  contract: { sha256: string; pdfUrl: string; nftId: string; nftOwner: string; mintTx: string };
  escrow: {
    status: 'not funded' | 'locked' | 'released';
    amountXrp: number;
    walletAddress: string;
    fundTx?: string;
    releaseTx?: string;
    closeTx?: string;
    keys: Tally;
    passports: Tally;
    approvals: Tally;
  };
  stages: Stage[];
  gate?: { passed: boolean; findings: { code?: string; ok?: boolean; passed?: boolean; message?: string }[] };
  releasedAt?: string;
  releasedBy?: Who[];
  ledger: { network: string; explorerBase?: string };
}

const BASE = `${API_BASE}/demo`;

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init);
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return (await res.json()) as T;
}
const post = <T,>(path: string, body: BodyInit | object) =>
  call<T>(
    path,
    body instanceof FormData
      ? { method: 'POST', body }
      : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) },
  );

export const registerParticipant = (name: string) => post<Participant>('/participants', { name });
export const approveStage = (id: string, rid: string, stage: number) =>
  post<Deal>(`/deals/${id}/approve`, { rid, stage });
export const createDeal = (form: FormData) => post<Deal>('/deals', form);

export const participantsKey = ['demo', 'participants'] as const;
export const dealsKey = (status?: string) => ['demo', 'deals', status ?? 'all'] as const;
export const dealKey = (id: string) => ['demo', 'deal', id] as const;

export const useParticipants = () =>
  useQuery({ queryKey: participantsKey, queryFn: () => call<Participant[]>('/participants'), staleTime: 0 });
export const useDeals = (status?: 'locked' | 'released') =>
  useQuery({
    queryKey: dealsKey(status),
    queryFn: () => call<Deal[]>(`/deals${status ? `?status=${status}` : ''}`),
    staleTime: 0,
  });
export const useDeal = (id: string) =>
  useQuery({ queryKey: dealKey(id), queryFn: () => call<Deal>(`/deals/${id}`), staleTime: 0 });

const RID_KEY = 'legx.demo.rid';
export const savedRid = () => {
  try {
    return localStorage.getItem(RID_KEY) ?? undefined;
  } catch {
    return undefined;
  }
};
export const saveRid = (rid: string) => {
  try {
    localStorage.setItem(RID_KEY, rid);
  } catch {
    // private window: the page still works for this visit
  }
};

/** The progress artifact: any feed row for the deal refetches the deal queries, so the dots follow the server. */
export function LiveProgress({ deal, compact }: { deal: Deal; compact?: boolean }) {
  const qc = useQueryClient();
  useLiveDeal(deal.dealId);
  const rows = useQuery<LiveRows>({ queryKey: liveRowsKey(deal.dealId), queryFn: skipToken });
  const seq = rows.data?.lastSeq ?? -1;
  useEffect(() => {
    if (seq < 0) return;
    void qc.invalidateQueries({ queryKey: ['demo'] });
  }, [seq, qc]);
  return <DealProgress stages={deal.stages} {...(compact ? { compact } : {})} />;
}
