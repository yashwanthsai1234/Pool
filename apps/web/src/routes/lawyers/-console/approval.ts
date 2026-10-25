// The lawyer's approval prompt (P4.4-11, P4.4-12). Before the firm HSM co-signs, the console decodes the exact bytes the
// slot would sign, shows what they mean and their hash, and asks for a user-verified WebAuthn approval over that hash.
// The text comes from the bytes, never from the coordinator's description: a description that disagrees is shown as a
// mismatch and no approval is offered for it.
// Source: DESIGN 6.4 ("A second holder never signs on its own say-so"); https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
import { bytesToHex, hexToBytes, sha256 } from '@legx/core/dealcore';
import type { SlotPublic } from '@legx/core/frost';
import { messageFor } from '@legx/vault/vault';
import { decode } from 'xrpl';
import { type ApprovalView, type ApprovalWire, ConsoleError, type SignRequest, type SlotPort } from './ports.ts';

/** What the coordinator says the request is. Compared with the decoded bytes, never trusted. */
export interface Described {
  what?: string;
  destination?: string;
  amount?: string;
}

const text = (b: Uint8Array) => new TextDecoder().decode(b);
const amountText = (a: unknown): string => (typeof a === 'string' ? `${a} drops` : JSON.stringify(a));

/** The 4-byte multi-signing prefix and the trailing 20-byte account ID wrap the serialized transaction. */
function decodeMultisign(bytes: Uint8Array): Record<string, unknown> {
  // Source: https://xrpl.org/docs/references/protocol/binary-format (signing prefixes: "SMT\0" for multi-signing)
  if (bytes.length < 25 || text(bytes.slice(0, 3)) !== 'SMT' || bytes[3] !== 0)
    throw new Error('not a multisign message');
  return decode(bytesToHex(bytes.slice(4, -20)).toUpperCase()) as Record<string, unknown>;
}

function describeBytes(request: SignRequest, bytes: Uint8Array): { lines: string[]; fields: Record<string, string> } {
  if (request.kind === 'xrpl-multisign') {
    const tx = decodeMultisign(bytes);
    const fields: Record<string, string> = { what: String(tx.TransactionType) };
    for (const k of ['Account', 'Destination', 'DestinationTag', 'Fee', 'Sequence'] as const)
      if (tx[k] !== undefined) fields[k] = String(tx[k]);
    if (tx.Amount !== undefined) fields.amount = amountText(tx.Amount);
    if (tx.Destination !== undefined) fields.destination = String(tx.Destination);
    const to =
      tx.Destination !== undefined
        ? ` to ${fields.destination}${tx.DestinationTag === undefined ? '' : ` (tag ${tx.DestinationTag})`}`
        : '';
    return {
      fields,
      lines: [
        `${fields.what}${to}`,
        ...(fields.amount ? [`Amount: ${fields.amount}`] : []),
        `From the deal wallet ${fields.Account}`,
      ],
    };
  }
  // OD-33: the single-signed CredentialAccept belongs to the client slots; a lawyer slot never signs it.
  if (request.kind === 'xrpl-single') throw new Error('not a lawyer message');
  if (request.kind === 'tagged') {
    const parts = request.parts.map((p) => (/^[\x20-\x7e]+$/.test(text(p)) ? text(p) : bytesToHex(p)));
    return {
      fields: { what: request.tag, ...Object.fromEntries(parts.map((p, i) => [`part${i}`, p])) },
      lines: [`Signs ${request.tag}`, ...parts.map((p, i) => `Field ${i + 1}: ${p}`)],
    };
  }
  const st = JSON.parse(
    text(Uint8Array.from(atob(JSON.parse(text(request.envelope)).payload), (c) => c.charCodeAt(0))),
  ) as {
    predicate?: { kind?: string; deal_id?: string; data?: { gate?: { ledger?: { ledger_index?: number } } } };
  };
  const p = st.predicate ?? {};
  const fields = { what: String(p.kind), deal: String(p.deal_id), ledger: String(p.data?.gate?.ledger?.ledger_index) };
  return { fields, lines: [`Signs the record ${fields.what} for deal ${fields.deal}`, `Gate ledger ${fields.ledger}`] };
}

/** Decodes the exact bytes the slot would sign (the same function the vault and the HSM use). */
function reviewRequest(pub: SlotPublic, request: SignRequest, claimed?: Described): ApprovalView {
  let bytes: Uint8Array;
  let described: { lines: string[]; fields: Record<string, string> };
  try {
    bytes = messageFor(pub, request);
    described = describeBytes(request, bytes);
  } catch {
    throw new ConsoleError('UNDECODABLE', 'the console cannot read this message, so it cannot be approved');
  }
  const mismatch: string[] = [];
  const f = described.fields;
  if (claimed?.what !== undefined && claimed.what !== f.what)
    mismatch.push(`says ${claimed.what}, the bytes are ${f.what}`);
  if (claimed?.destination !== undefined && claimed.destination !== f.destination)
    mismatch.push(`says destination ${claimed.destination}, the bytes pay ${f.destination ?? 'nobody'}`);
  if (claimed?.amount !== undefined && claimed.amount !== f.amount)
    mismatch.push(`says amount ${claimed.amount}, the bytes carry ${f.amount ?? 'none'}`);
  return { lines: described.lines, fields: f, hash: bytesToHex(sha256(bytes)), mismatch };
}

/**
 * The only way the console asks the slot to sign. Nothing is sent to the HSM unless the lawyer confirmed the decoded
 * view and the WebAuthn approval is over that same hash.
 */
export async function signWithApproval(
  o: {
    slot: SlotPort;
    confirm: (v: ApprovalView) => Promise<boolean>;
    requestApproval: (hash: Uint8Array) => Promise<ApprovalWire>;
  },
  request: SignRequest,
  claimed?: Described,
): Promise<Uint8Array> {
  const view = reviewRequest(o.slot.pub, request, claimed);
  if (view.mismatch.length > 0) {
    // The prompt still shows what the bytes mean and the mismatch, but offers no approval for the false summary.
    await o.confirm(view).catch(() => false);
    throw new ConsoleError('SUMMARY_MISMATCH', view.mismatch.join('; '));
  }
  if (!(await o.confirm(view))) throw new ConsoleError('APPROVAL_CANCELLED');
  const approval = await o.requestApproval(hexToBytes(view.hash)).catch(() => {
    throw new ConsoleError('APPROVAL_REFUSED');
  });
  if (approval.message_hash !== view.hash) throw new ConsoleError('APPROVAL_HASH_MISMATCH');
  return o.slot.sign(request, approval);
}
