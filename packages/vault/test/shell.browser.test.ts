// The shell setup key (DESIGN D17, 5.2 steps 5a to 5g): made on Alice's device, so the wallet address is known before the
// account holds XRP; it signs only the setup transactions, never anything that moves money, and is wiped at DisableMaster.
import { ed25519 } from '@noble/curves/ed25519.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { decode, deriveAddress, encodeForSigning } from 'xrpl';
import { shellKey } from '../src/shell.ts';
import { dealId, freshDb } from './helpers.ts';

const base = (account: string) => ({ Account: account, Sequence: 5, Fee: '10', LastLedgerSequence: 100 });
const setFlag = (account: string, SetFlag: number) => ({ TransactionType: 'AccountSet', SetFlag, ...base(account) });

async function made() {
  const keys = shellKey({ role: 'alice', dbName: freshDb() });
  const id = dealId();
  const { publicKey, address } = await keys.create(id);
  return { keys, id, publicKey, address };
}

describe('shell key', () => {
  it('is made once, and its address derives from its public key', async () => {
    const { keys, id, publicKey, address } = await made();
    expect(publicKey).toMatch(/^ED[0-9A-F]{64}$/);
    expect(address).toBe(deriveAddress(publicKey));
    expect(await keys.create(id)).toEqual({ publicKey, address });
  });

  it('signs a setup transaction: the blob carries a strict Ed25519 signature over the signing bytes', async () => {
    const { keys, id, publicKey, address } = await made();
    const tx = { TransactionType: 'AccountSet', Domain: '01AB', ...base(address) };
    const blob = await keys.sign(id, tx);
    const signed = decode(blob) as Record<string, string>;
    expect(signed.SigningPubKey).toBe(publicKey);
    const msg = hexToBytes(encodeForSigning({ ...tx, SigningPubKey: publicKey } as never));
    expect(
      ed25519.verify(hexToBytes(signed.TxnSignature as string), msg, hexToBytes(publicKey).slice(1), { zip215: false }),
    ).toBe(true);
  });

  it.each([
    ['Payment', { TransactionType: 'Payment', Destination: 'rHhr2iRBgp3ZzzNH4YGQ59G7VAiGPEWj7f', Amount: '1' }],
    [
      'EscrowCreate',
      { TransactionType: 'EscrowCreate', Destination: 'rHhr2iRBgp3ZzzNH4YGQ59G7VAiGPEWj7f', Amount: '1' },
    ],
    ['NFTokenCreateOffer', { TransactionType: 'NFTokenCreateOffer', Amount: '1' }],
    ['SetRegularKey', { TransactionType: 'SetRegularKey', RegularKey: 'rHhr2iRBgp3ZzzNH4YGQ59G7VAiGPEWj7f' }],
    ['AccountSet with a delegate flag', { TransactionType: 'AccountSet', SetFlag: 5 }],
    [
      'AccountDelete to a stranger',
      { TransactionType: 'AccountDelete', Destination: 'rHhr2iRBgp3ZzzNH4YGQ59G7VAiGPEWj7f' },
    ],
  ])('refuses %s', async (_n, extra) => {
    const { keys, id, address } = await made();
    await expect(keys.sign(id, { ...extra, ...base(address) })).rejects.toMatchObject({ code: 'MESSAGE_REFUSED' });
  });

  it('refuses a transaction for another account, or one that already carries a signing key', async () => {
    const { keys, id, address } = await made();
    await expect(keys.sign(id, setFlag('rHhr2iRBgp3ZzzNH4YGQ59G7VAiGPEWj7f', 9))).rejects.toMatchObject({
      code: 'MESSAGE_REFUSED',
    });
    await expect(keys.sign(id, { ...setFlag(address, 9), SigningPubKey: 'AB' })).rejects.toMatchObject({
      code: 'MESSAGE_REFUSED',
    });
  });

  it('DisableMaster is the last signature: the key is wiped and never signs or returns again', async () => {
    const { keys, id, address } = await made();
    await keys.sign(id, setFlag(address, 4));
    await expect(keys.sign(id, setFlag(address, 9))).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(keys.create(id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});
