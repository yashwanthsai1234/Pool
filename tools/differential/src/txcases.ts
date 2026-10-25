// T-Z-02: a random transaction from one of the 19 builders of @legx/xrpl. Every builder is covered in turn.
import { makeCondition } from '@legx/core/dealcore';
import {
  type BuildCtx,
  build0a,
  build0b,
  build1,
  build2,
  build3,
  build5a,
  build5b,
  build5c,
  build5d,
  build5e,
  build5f,
  build5g,
  build7,
  build8,
  build9,
  buildAnchor,
  buildEscrowCancel,
  buildSignerListRotation,
  buildTicketCreate,
  DISALLOW_KINDS,
  type Slot,
} from '@legx/xrpl';
import { address, dropsStr, edKey, hex, hexUp, ledgerSeq, payout } from './gen.ts';
import type { Prng } from './prng.ts';

type Tx = Record<string, unknown>;

const slot = (r: Prng): Slot => (r.chance(0.5) ? { sequence: ledgerSeq(r) } : { ticketSequence: ledgerSeq(r) });

const BUILDERS: readonly ((r: Prng, ctx: BuildCtx) => object)[] = [
  (r, c) =>
    build0a(
      { issuer: address(r), subject: address(r), barVerificationSha256: r.bytes(32), closeTime: r.range(1, 2 ** 31) },
      c,
    ),
  (r, c) => build0b({ subject: address(r), issuer: address(r) }, c),
  (r, c) =>
    build5e({ shell: address(r), subject: address(r), side: r.pick(['A', 'B'] as const), bindingSig: r.bytes(64) }, c),
  (r, c) => build5f({ subject: address(r), shell: address(r), side: r.pick(['A', 'B'] as const) }, c),
  (r, c) =>
    build3(
      {
        alice: address(r),
        shell: address(r),
        amount: dropsStr(r),
        condition: makeCondition(r.bytes(32)).condition,
        closeTime: r.range(1, 2 ** 31),
        days: r.range(1, 3650),
      },
      c,
    ),
  (r, c) => {
    const { condition, fulfillment } = makeCondition(r.bytes(32));
    return build7(
      {
        releaser: address(r),
        owner: address(r),
        offerSequence: ledgerSeq(r),
        condition,
        fulfillment,
        gateLeafHash: r.bytes(32),
      },
      c,
    );
  },
  (r, c) => buildEscrowCancel({ account: address(r), owner: address(r), offerSequence: ledgerSeq(r) }, c),
  (r, c) => build5a({ shell: address(r), signers: [address(r), address(r), address(r), address(r)] }, c),
  (r, c) => build5b({ shell: address(r), contractRoot: r.bytes(32), dealSeal: r.bytes(32) }, c),
  (r, c) => build5c({ shell: address(r), kind: r.pick(DISALLOW_KINDS) }, c),
  (r, c) => build5d({ shell: address(r), releaser: address(r) }, c),
  (r, c) => build5g({ shell: address(r) }, c),
  (r, c) =>
    build1(
      {
        lawyerOpsA: address(r),
        signedContractSeal: r.bytes(32),
        memo: { lawyerPubA: edKey(r), lawyerPubB: edKey(r), sigLA: r.bytes(64), sigLB: r.bytes(64) },
      },
      c,
    ),
  (r, c) =>
    buildAnchor(
      {
        anchorAccount: address(r),
        originHash: r.bytes(32),
        treeSize: BigInt(r.u32()) * BigInt(r.u32()) + BigInt(r.u32()),
        root: r.bytes(32),
      },
      c,
    ),
  (r, c) =>
    buildTicketCreate(
      { shell: address(r), count: r.range(1, 250), ...(r.chance(0.5) ? { sequence: ledgerSeq(r) } : {}) },
      c,
    ),
  (r, c) =>
    buildSignerListRotation({ shell: address(r), signers: [address(r), address(r), address(r), address(r)] }, c),
  (r, c) => build2({ alice: address(r), shell: address(r), amount: dropsStr(r) }, c),
  (r, c) => build8({ shell: address(r), payout: payout(r), amount: dropsStr(r), slot: slot(r) }, c),
  (r, c) =>
    build9(
      {
        shell: address(r),
        destination: address(r),
        ownerReserveDrops: dropsStr(r),
        ...(r.chance(0.5) ? { slot: slot(r) } : {}),
      },
      c,
    ),
];

export const BUILDER_COUNT = BUILDERS.length;

/** The `index`-th case: builders in turn (so each gets the same share), random inputs, random fee base and network. */
export function randomTx(r: Prng, index: number): Tx {
  const ctx: BuildCtx = {
    network: r.pick(['standalone', 'testnet', 'devnet'] as const),
    ...(r.chance(0.5) ? { baseFeeDrops: r.range(1, 5000) } : {}),
  };
  const tx = (BUILDERS[index % BUILDERS.length] as (r: Prng, c: BuildCtx) => object)(r, ctx) as Tx;
  // Half of the cases also carry a signature, and a quarter a Signers array, as a signed transaction does.
  if (r.chance(0.5)) {
    tx.SigningPubKey = hexUp(new Uint8Array([0xed, ...r.bytes(32)]));
    tx.TxnSignature = hexUp(r.bytes(64));
  }
  if (r.chance(0.25)) {
    tx.SigningPubKey = '';
    tx.Signers = Array.from({ length: r.range(1, 4) }, () => ({
      Signer: {
        Account: address(r),
        SigningPubKey: `ED${hex(r.bytes(32))}`.toUpperCase(),
        TxnSignature: hexUp(r.bytes(64)),
      },
    }));
  }
  return tx;
}
