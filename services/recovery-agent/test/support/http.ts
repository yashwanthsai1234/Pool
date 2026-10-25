// Signed API requests the way a client makes them (OD-5, OD-8).
import { randomBytes } from 'node:crypto';
import { API_AUTH_HEADER } from '@legx/contracts/api';
import { apiRequestMessage } from '@legx/coordinator/auth';
import { mldsaSign, toBase64 } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import type { HolderKeys } from '../../src/wire.ts';

export function signedRequest(
  keys: HolderKeys,
  method: 'GET' | 'POST',
  url: string,
  body?: unknown,
  over: { ledgerIndex?: number; omitAuth?: boolean } = {},
) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  const nonce = randomBytes(32).toString('hex');
  const ledgerIndex = over.ledgerIndex ?? 1000;
  const msg = apiRequestMessage(method, url, new TextEncoder().encode(payload ?? ''), nonce, ledgerIndex);
  const auth = {
    nonce,
    ledgerIndex,
    signatures: [
      { keyid: `${keys.keyId}#ed25519`, sig: toBase64(ed25519.sign(msg, keys.edSecret)) },
      {
        keyid: `${keys.keyId}#ml-dsa-65`,
        sig: toBase64(mldsaSign('ml-dsa-65', keys.pqSecret, msg, 'legx/api-request/v1' as never)),
      },
    ],
  };
  return {
    method,
    url,
    headers: {
      ...(over.omitAuth ? {} : { [API_AUTH_HEADER]: JSON.stringify(auth) }),
      ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(payload === undefined ? {} : { payload }),
  };
}
