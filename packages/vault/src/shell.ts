// The shell setup key (DESIGN D1, D17, 5.2 steps 5a to 5g; IMPLEMENTATION table "5a to 5g"). Alice's device makes it so the
// deal wallet's address is known before the account holds any XRP. It is a non-extractable WebCrypto Ed25519 key, and it
// signs only the setup transactions of the lock sequence for the shell's own account. Anything that moves money, makes an
// offer, or adds another way in (regular key, delegate, escrow, payment) is refused, so a hostile page cannot use it to drain
// the wallet (T-A-01 to T-A-03). `AccountSet` with `SetFlag` 4 (DisableMaster) is its last use: the key is wiped after it.
// Source: https://xrpl.org/docs/references/protocol/transactions/types/accountset (SetFlag values)
// Source: https://w3c.github.io/webcrypto/#ed25519 ; xrpl.js `encodeForSigning`, ed25519 signs the signing bytes unhashed
import { DealId } from '@legx/contracts/values';
import { bytesToHex } from '@noble/hashes/utils.js';
import { deriveAddress, encode, encodeForSigning } from 'xrpl';
import { VaultError } from './errors.ts';
import type { PartyRole } from './rules.ts';
import { Store } from './store.ts';

type Row = { id: string; role: PartyRole; privateKey?: CryptoKey; publicKey?: string; wiped?: boolean };
export type ShellInfo = { publicKey: string; address: string };

const DISABLE_MASTER = 4;
/** DepositAuth, then DisallowIncoming NFTokenOffer, Check, PayChan, Trustline (5b, 5c), and DisableMaster (5g). */
const SET_FLAGS = new Set([4, 9, 12, 13, 14, 15]);
const TYPES = new Set(['SignerListSet', 'AccountSet', 'DepositPreauth', 'CredentialCreate']);
// AccountDelete (closing an abandoned shell, 5.2) is not signed here: its Destination must come from the verified payout in the
// seal, which does not exist yet at that point (known gap, status file).

export function shellKey(opts: { role: PartyRole; dbName?: string }) {
  const store = new Store(opts.dbName ?? 'legx-vault');
  const idOf = (dealId: string) => {
    if (!DealId.safeParse(dealId).success) throw new VaultError('INPUT_INVALID');
    return `${dealId}:${opts.role}:shell`;
  };
  const live = async (dealId: string) => {
    const r = await store.get<Row>('enrollment', idOf(dealId));
    if (!r?.privateKey || !r.publicKey || r.wiped) throw new VaultError('NOT_FOUND');
    return { ...r, privateKey: r.privateKey, publicKey: r.publicKey };
  };
  const info = (publicKey: string): ShellInfo => ({ publicKey, address: deriveAddress(publicKey) });

  return {
    /** Makes the key once; later calls return the same public key and address. A wiped key is gone for good. */
    async create(dealId: string): Promise<ShellInfo> {
      const have = await store.get<Row>('enrollment', idOf(dealId));
      if (have?.wiped) throw new VaultError('NOT_FOUND');
      if (have?.publicKey) return info(have.publicKey);
      const kp = (await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify'])) as CryptoKeyPair;
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
      const publicKey = `ED${bytesToHex(raw).toUpperCase()}`;
      await store.put('enrollment', { id: idOf(dealId), role: opts.role, privateKey: kp.privateKey, publicKey });
      return info(publicKey);
    },

    /** The signed transaction blob (uppercase hex) of one allowed setup transaction of the shell's own account. */
    async sign(dealId: string, tx: Record<string, unknown>): Promise<string> {
      const key = await live(dealId);
      const address = deriveAddress(key.publicKey);
      const flag = tx.SetFlag;
      const allowed =
        typeof tx.TransactionType === 'string' &&
        TYPES.has(tx.TransactionType) &&
        tx.Account === address &&
        tx.SigningPubKey === undefined &&
        tx.TxnSignature === undefined &&
        tx.Signers === undefined &&
        tx.RegularKey === undefined &&
        tx.Delegate === undefined &&
        (tx.TransactionType !== 'AccountSet' || flag === undefined || SET_FLAGS.has(Number(flag)));
      if (!allowed) throw new VaultError('MESSAGE_REFUSED');
      const body = { ...tx, SigningPubKey: key.publicKey };
      const msg = Uint8Array.from(encodeForSigning(body as never).match(/../g) ?? [], (h) => Number.parseInt(h, 16));
      const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', key.privateKey, msg as BufferSource));
      const blob = encode({ ...body, TxnSignature: bytesToHex(sig).toUpperCase() } as never);
      if (tx.TransactionType === 'AccountSet' && Number(flag) === DISABLE_MASTER) {
        await store.put('enrollment', { id: idOf(dealId), role: opts.role, wiped: true });
      }
      return blob;
    },
  };
}
