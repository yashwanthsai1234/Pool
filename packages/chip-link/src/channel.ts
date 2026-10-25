// The local end-to-end channel. The console shows a QR code holding a one-time X-Wing public key, a session id and the
// 8-byte AA challenge. The helper HPKE-seals the transfer to that key; the console opens it once.
// Source: https://www.rfc-editor.org/rfc/rfc9180 (HPKE base mode, info and aad)
// Source: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/

import { aaChallenge } from '@legx/core/passport/activeAuth';
import { openPackage, PACKAGE_SUITES, sealPackage, XWING_SUITE } from '@legx/core/pq';
import { bytesToHex, concatBytes, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { base64urlnopad } from '@scure/base';

const QR_PREFIX = 'legxchip1';
const suite = PACKAGE_SUITES[XWING_SUITE];

export interface QrContent {
  readonly sessionId: Uint8Array;
  /** RND.IFD for Active Authentication: the first 8 bytes of presenceMsg (OD-23). */
  readonly challenge: Uint8Array;
  readonly publicKey: Uint8Array;
}

/** `legxchip1:<session hex>:<challenge hex>:<public key base64url>`. Source: DESIGN.md 6.15 */
export function encodeQr(q: QrContent): string {
  return [QR_PREFIX, bytesToHex(q.sessionId), bytesToHex(q.challenge), base64urlnopad.encode(q.publicKey)].join(':');
}

export function parseQr(s: string): QrContent | undefined {
  const [prefix, sid, ch, pk, ...rest] = s.split(':');
  if (prefix !== QR_PREFIX || pk === undefined || rest.length > 0) return undefined;
  if (!/^[0-9a-f]{32}$/.test(sid ?? '') || !/^[0-9a-f]{16}$/.test(ch ?? '')) return undefined;
  try {
    return {
      sessionId: hexToBytes(sid as string),
      challenge: hexToBytes(ch as string),
      publicKey: base64urlnopad.decode(pk),
    };
  } catch {
    return undefined;
  }
}

export interface Session {
  readonly qr: string;
  readonly sessionId: Uint8Array;
  readonly challenge: Uint8Array;
  /** The one-time secret; `open` zeroes it after the first successful use. */
  readonly secretKey: Uint8Array;
  used: boolean;
}

export async function createSession(presenceMsg: Uint8Array): Promise<Session> {
  const { publicKey, secretKey } = await (suite as NonNullable<typeof suite>).keygen();
  const sessionId = randomBytes(16);
  const challenge = aaChallenge(presenceMsg);
  return { qr: encodeQr({ sessionId, challenge, publicKey }), sessionId, challenge, secretKey, used: false };
}

const aadFor = (q: { sessionId: Uint8Array; challenge: Uint8Array }) => concatBytes(q.sessionId, q.challenge);

/** What goes over the network: the HPKE encapsulation and ciphertext. Nothing else. */
export interface Sealed {
  readonly enc: Uint8Array;
  readonly ct: Uint8Array;
}

/** Helper side: seals the plaintext to the key in the QR. Binding the session and challenge as aad stops a replay into another session. */
export async function sealToQr(qr: QrContent, plaintext: Uint8Array): Promise<Sealed> {
  const { enc, ct } = await sealPackage('chip-link', qr.publicKey, plaintext, aadFor(qr));
  return { enc, ct };
}

export type OpenCode = 'SESSION_USED' | 'OPEN_FAILED';

/** Console side: opens once. A failed attempt does not burn the session, so noise on the network cannot deny service. */
export async function openSealed(
  s: Session,
  sealed: Sealed,
): Promise<{ ok: true; plaintext: Uint8Array } | { ok: false; code: OpenCode }> {
  if (s.used) return { ok: false, code: 'SESSION_USED' };
  const r = await openPackage(
    'chip-link',
    { suite: XWING_SUITE, enc: sealed.enc, ct: sealed.ct },
    s.secretKey,
    aadFor(s),
  );
  if (!r.ok) return { ok: false, code: 'OPEN_FAILED' };
  s.used = true;
  s.secretKey.fill(0);
  return { ok: true, plaintext: r.plaintext };
}
