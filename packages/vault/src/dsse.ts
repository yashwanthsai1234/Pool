// What the frame's evidence signer will sign (I-W-10): the DSSE pre-authentication encoding of one of the two evidence payload
// types, whose JSON body names the deal the key was made for. Anything else (free text, an API request, another deal's
// statement, a body with the wrong length) is refused before a key is touched.
// Source: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md (v1.0.2, PAE: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body)
import { ATTEST_PAYLOAD_TYPE, PAYLOAD_TYPE } from '@legx/core/evidence';

const enc = new TextEncoder();

/** The deal a statement of type `type` names in its JSON body (`predicate.deal_id` for events, `deal_id` for attestations). */
const dealOfBody = (type: string, body: unknown): unknown => {
  const o = (typeof body === 'object' && body !== null ? body : {}) as {
    deal_id?: unknown;
    predicate?: { deal_id?: unknown };
  };
  return type === PAYLOAD_TYPE ? o.predicate?.deal_id : o.deal_id;
};

/** True when `msg` is the PAE of an evidence statement of `dealId`. */
export function dsseDealOf(msg: Uint8Array, dealId: string): boolean {
  for (const type of [PAYLOAD_TYPE, ATTEST_PAYLOAD_TYPE]) {
    const t = enc.encode(type);
    const head = enc.encode(`DSSEv1 ${t.length} ${type} `);
    if (msg.length <= head.length || !head.every((b, i) => msg[i] === b)) continue;
    const rest = msg.subarray(head.length);
    const space = rest.indexOf(0x20);
    const len = new TextDecoder().decode(rest.subarray(0, Math.max(space, 0)));
    if (space < 1 || !/^(0|[1-9]\d{0,8})$/.test(len)) return false;
    const body = rest.subarray(space + 1);
    if (body.length !== Number(len)) return false;
    try {
      return dealOfBody(type, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body))) === dealId;
    } catch {
      return false;
    }
  }
  return false;
}
