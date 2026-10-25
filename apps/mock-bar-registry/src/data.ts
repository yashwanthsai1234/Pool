// Source: IMPLEMENTATION.md section 3.3 (4 fake lawyers: 2 active, 1 struck off, 1 lapsed). All names and numbers are invented.
export const DEMO_BANNER = 'DEMO REGISTRY - NOT A REAL BAR REGISTRY';

type LawyerStatus = 'active' | 'struck_off' | 'lapsed';

export interface Lawyer {
  jurisdiction: string;
  barNumber: string;
  name: string;
  status: LawyerStatus;
}

export const LAWYERS: readonly Lawyer[] = [
  { jurisdiction: 'XA-DM', barNumber: 'DEMO-0001', name: 'Demo Lawyer Alpha', status: 'active' },
  { jurisdiction: 'XA-DM', barNumber: 'DEMO-0002', name: 'Demo Lawyer Bravo', status: 'active' },
  { jurisdiction: 'XA-DM', barNumber: 'DEMO-0003', name: 'Demo Lawyer Charlie', status: 'struck_off' },
  { jurisdiction: 'XA-DM', barNumber: 'DEMO-0004', name: 'Demo Lawyer Delta', status: 'lapsed' },
];

// Exact match on both fields. Callers validate the format first (see server.ts).
export function findLawyer(jurisdiction: string, barNumber: string): Lawyer | undefined {
  return LAWYERS.find((lawyer) => lawyer.jurisdiction === jurisdiction && lawyer.barNumber === barNumber);
}
