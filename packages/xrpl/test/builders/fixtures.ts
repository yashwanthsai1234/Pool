// Fixed inputs for every builder: deterministic wallets, fixed bytes. Used by the snapshot and shape tests.
import { sha256 } from '@legx/core/dealcore';
import { ECDSA, Wallet } from 'xrpl';
import type { BuildCtx } from '../../src/builders/index.ts';
import {
  build0a,
  build0b,
  build0c,
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
} from '../../src/builders/index.ts';

export const fill = (n: number, len = 32) => new Uint8Array(len).fill(n);
const wallet = (n: number) => Wallet.fromEntropy(fill(n, 16), { algorithm: ECDSA.ed25519 }).classicAddress;
export const A = {
  issuer: wallet(1),
  lawyerA: wallet(2),
  lawyerB: wallet(3),
  alice: wallet(4),
  bob: wallet(5),
  shell: wallet(6),
  x1: wallet(7),
  x2: wallet(8),
  x3: wallet(9),
  x4: wallet(10),
  anchor: wallet(11),
  payout: wallet(12),
};
export const ADDRESSES = Object.values(A);
export const CTX: BuildCtx = { network: 'standalone' };
export const CLOSE = 800_000_000;
export const edPub = (n: number) => Wallet.fromEntropy(fill(n, 16), { algorithm: ECDSA.ed25519 }).publicKey;
export const CONDITION = `A0258020${'AB'.repeat(32)}810120`;
export const FULFILLMENT = `A0228020${'CD'.repeat(32)}`;
export const MEMO = { lawyerPubA: edPub(1), lawyerPubB: edPub(2), sigLA: fill(3, 64), sigLB: fill(4, 64) };

export const ALL = () => ({
  '0a': build0a({ issuer: A.issuer, subject: A.lawyerA, barVerificationSha256: fill(7), closeTime: CLOSE }, CTX),
  '0b': build0b({ subject: A.lawyerA, issuer: A.issuer }, CTX),
  '0c': build0c({ issuer: A.issuer, subject: A.lawyerA }, CTX),
  '1': build1({ lawyerOpsA: A.lawyerA, signedContractSeal: fill(8), memo: MEMO }, CTX),
  '2': build2({ alice: A.alice, shell: A.shell, amount: '2500000' }, CTX),
  '3': build3(
    { alice: A.alice, shell: A.shell, amount: '50000000', condition: CONDITION, closeTime: CLOSE, days: 3 },
    CTX,
  ),
  '5a': build5a({ shell: A.shell, signers: [A.x1, A.x2, A.x3, A.x4] }, CTX),
  '5b': build5b({ shell: A.shell, contractRoot: fill(0x11), dealSeal: fill(0x22) }, CTX),
  '5c-nftOffer': build5c({ shell: A.shell, kind: 'nftOffer' }, CTX),
  '5c-check': build5c({ shell: A.shell, kind: 'check' }, CTX),
  '5c-payChannel': build5c({ shell: A.shell, kind: 'payChannel' }, CTX),
  '5c-trustLine': build5c({ shell: A.shell, kind: 'trustLine' }, CTX),
  '5d': build5d({ shell: A.shell, releaser: A.lawyerB }, CTX),
  '5e-A': build5e({ shell: A.shell, subject: A.alice, side: 'A', bindingSig: fill(9, 64) }, CTX),
  '5e-B': build5e({ shell: A.shell, subject: A.bob, side: 'B', bindingSig: fill(10, 64) }, CTX),
  '5f-A': build5f({ subject: A.alice, shell: A.shell, side: 'A' }, CTX),
  '5f-B': build5f({ subject: A.bob, shell: A.shell, side: 'B' }, CTX),
  '5g': build5g({ shell: A.shell }, CTX),
  '7': build7(
    {
      releaser: A.lawyerB,
      owner: A.alice,
      offerSequence: 42,
      condition: CONDITION,
      fulfillment: FULFILLMENT,
      gateLeafHash: sha256(fill(5)),
    },
    CTX,
  ),
  '8': build8({ shell: A.shell, payout: `${A.payout}:12345`, amount: '50000000', slot: { sequence: 77 } }, CTX),
  '9': build9({ shell: A.shell, destination: A.alice, ownerReserveDrops: '200000', slot: { sequence: 78 } }, CTX),
  exp: buildEscrowCancel({ account: A.bob, owner: A.alice, offerSequence: 42 }, CTX),
  anchor: buildAnchor({ anchorAccount: A.anchor, originHash: fill(1), treeSize: 1234n, root: fill(2) }, CTX),
  ticket: buildTicketCreate({ shell: A.shell, count: 2 }, CTX),
  rotation: buildSignerListRotation({ shell: A.shell, signers: [A.x4, A.x3, A.x2, A.x1] }, CTX),
});
