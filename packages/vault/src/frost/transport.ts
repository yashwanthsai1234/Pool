// The relay as the FROST code sees it: contracts `FrostRelayPort` plus opening a session. In the app it runs over the
// typed API client (`frost.openSession`, `frost.send`, `frost.receive`, task 4.1b); in tests over MSW and an in-memory
// relay. Only signed, public or HPKE-sealed messages pass through it (P4.7-09).
// Source: packages/contracts/src/api.ts (`frost` routes), services/coordinator/src/frost/routes.ts
import type { FrostRelayPort, RelayedMessage } from '@legx/contracts/ports';
import { fromBase64Strict } from '@legx/core/pq';
import type { HolderInfo, Signed } from './wire.ts';

export type Purpose = 'dkg' | 'sign' | 'refresh' | 'repair';

export interface RelayPort extends FrostRelayPort {
  /**
   * Opens a session of the slot's three holders. For signing, `pair` names the two holders asked to sign. The contract
   * has no field for it, but 3.9's relay asks the first two participants as listed, so `apiRelay` lists the pair first.
   */
  openSession(input: {
    purpose: Purpose;
    holders: readonly HolderInfo[];
    pair?: readonly [string, string];
  }): Promise<string>;
}

/** The part of the API client the relay needs (structural, so the vault does not depend on the web app). */
export interface FrostApi {
  frost: {
    openSession(input: {
      dealId: string;
      slot: string;
      purpose: Purpose;
      participants: { identifier: string; keyId: string; role: string }[];
    }): Promise<{ sessionId: string }>;
    send(input: { sessionId: string; message: Signed }): Promise<{ seq: number }>;
    receive(input: { sessionId: string; recipient: string; afterSeq: number }): Promise<{ messages: RelayedMessage[] }>;
  };
}

const sessionOf = (m: Signed): string => {
  const raw = fromBase64Strict(m.payload);
  return raw ? String((JSON.parse(new TextDecoder().decode(raw)) as { session_id?: unknown }).session_id) : '';
};

/** The relay over the typed API client. */
export function apiRelay(api: FrostApi, deal: { dealId: string; slot: string }): RelayPort {
  return {
    async openSession({ purpose, holders, pair }) {
      const first = (h: HolderInfo) => (pair?.includes(h.identifier) ? 0 : 1);
      const ordered = [...holders].sort((a, b) => first(a) - first(b));
      const participants = ordered.map((h) => ({ identifier: h.identifier, keyId: h.keyId, role: h.role }));
      return (await api.frost.openSession({ ...deal, purpose, participants })).sessionId;
    },
    send: (message) => api.frost.send({ sessionId: sessionOf(message), message }),
    async receive(sessionId, recipient, afterSeq) {
      return (await api.frost.receive({ sessionId, recipient, afterSeq })).messages;
    },
  };
}
