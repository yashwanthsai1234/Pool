// A client slot set up end to end with real vaults: the DKG through the relay (phone, second device, recovery agent),
// the phone's share 1 and the second device's share 2 stored by task 4.2's vault, and the relay co-signer between them.
import type { KeyId } from '@legx/contracts/values';
import { holderId, type KeyShare, type SlotPublic } from '@legx/core/frost';
import type { SealedDeal, SignRequest } from '@legx/core/frostRules';
import { mldsaSign, pqKeygen } from '@legx/core/pq';
import { enrollmentKeys, type PqHalf } from '../../src/enrollment.ts';
import { xwingShareCipher } from '../../src/frost/cipher.ts';
import { relayCoSigner, serveRelayCoSign } from '../../src/frost/cosign.ts';
import { openerSessions, runSlotDkg } from '../../src/frost/dkg.ts';
import { FrostHolder } from '../../src/frost/holder.ts';
import { vaultPartyKeys } from '../../src/frost/keys.ts';
import { keyDirectory } from '../../src/frost/pinning.ts';
import type { HolderInfo, PartyKeys } from '../../src/frost/wire.ts';
import { createVault, messageFor, type Vault } from '../../src/vault.ts';
import { dealId, freshDb, sealedDeal } from '../helpers.ts';
import { MemoryRelay, type Party, party } from './world.ts';

function pqHalf(): PqHalf {
  const k = pqKeygen();
  return {
    keyId: `pq-${crypto.randomUUID()}` as KeyId,
    publicKey: k.publicKey,
    sign: async (msg, ctx) => mldsaSign('ml-dsa-65', k.secretKey, msg, ctx),
  };
}

export type Device = { keys: PartyKeys; info: HolderInfo; dbName: string };

/** A device with its own vault database and WebCrypto enrollment key. */
export async function device(id: string, index: number, role: HolderInfo['role'], label: string): Promise<Device> {
  const dbName = freshDb();
  const { keys, info } = await vaultPartyKeys({
    enrollment: enrollmentKeys({ role: 'alice', dbName }),
    dealId: id,
    keyId: `key-${crypto.randomUUID()}`,
    pq: pqHalf(),
    identifier: holderId(index),
    role,
    deviceId: `${label}-${dbName}`,
    label,
  });
  return { keys, info, dbName };
}

export const holderFor = (
  relay: MemoryRelay,
  id: string,
  holders: readonly HolderInfo[],
  index: number,
  keys: PartyKeys,
  slot: 'A' | 'LA' = 'A',
) =>
  new FrostHolder({
    index,
    keys,
    dealId: id,
    slot,
    holders,
    relay,
    cipher: xwingShareCipher,
    pinned: keyDirectory(holders),
    timeoutMs: 8_000,
  });

export type ClientSlot = Awaited<ReturnType<typeof clientDevices>>;

/** Phone + second device (both with vaults) + recovery agent; the DKG has run and both vaults hold their shares. */
export async function clientDevices(opts: { approve?: () => Promise<boolean> } = {}) {
  const id = dealId();
  const relay = new MemoryRelay();
  const phone = await device(id, 1, 'phone', 'Your phone');
  const second = await device(id, 2, 'second-authenticator', 'Your second device');
  const agent: Party = party(3, 'recovery-agent', 'Recovery agent (Example Recovery Ltd)');
  const holders = [phone.info, second.info, agent.info];
  relay.pin(...holders);
  const base = { dealId: id, slot: 'A' as const, holders, relay, pinned: keyDirectory(holders), timeoutMs: 8_000 };
  const [p, s, a] = await Promise.all([
    runSlotDkg({ ...base, sessions: openerSessions(relay, holders), local: [{ index: 1, keys: phone.keys }] }),
    runSlotDkg({ ...base, sessions: relay.joiner(), local: [{ index: 2, keys: second.keys }] }),
    runSlotDkg({ ...base, sessions: relay.joiner(), local: [{ index: 3, keys: agent.keys }] }),
  ]);
  if (!p.ready || !s.ready || !a.ready) throw new Error('DKG not ready');
  const pub: SlotPublic = p.pub;
  let deal: SealedDeal = sealedDeal(pub, 'A');
  const deals = async () => deal;
  const approveState = { ok: true, asked: 0 };
  const secondVault = createVault({
    role: 'alice',
    dbName: second.dbName,
    deals,
    approve:
      opts.approve ??
      (async () => {
        approveState.asked++;
        return approveState.ok;
      }),
  });
  const share1 = p.shares.get(1) as KeyShare;
  const share2 = s.shares.get(2) as KeyShare;
  const agentShare = a.shares.get(3) as KeyShare;
  const secrets = [share1.signingShare.slice(), share2.signingShare.slice(), agentShare.signingShare.slice()];
  await secondVault.storeSecondDeviceShare({ dealId: id, pub, share: share2 });
  const phoneHolder = holderFor(relay, id, holders, 1, phone.keys);
  const secondHolder = holderFor(relay, id, holders, 2, second.keys);
  const remoteCosign = secondVault.cosigner();
  const finished: Promise<void>[] = [];
  const cosigner = () =>
    relayCoSigner({
      holder: phoneHolder,
      relay,
      holders,
      dealId: id,
      slot: 'A',
      remote: 2,
      messageOf: (r: SignRequest) => messageFor(pub, r),
      start: async ({ sessionId, request }) => {
        const run = await serveRelayCoSign({
          holder: secondHolder,
          signer: {
            commit: ({ request: r }) => remoteCosign.commit({ dealId: id, request: r }),
            sign: (sess, list) => remoteCosign.sign(sess, list),
          },
          dealId: id,
          slot: 'A',
          sessionId,
          request,
          msg: messageFor(pub, request),
        });
        finished.push(run.finished.catch(() => undefined));
      },
    });
  const phoneVault: Vault = createVault({ role: 'alice', dbName: phone.dbName, deals, cosigner });
  await phoneVault.storeShares({ dealId: id, pub, share1, share2: { mode: 'second-device' } });
  return {
    id,
    relay,
    phone,
    second,
    agent,
    agentShare: { identifier: agentShare.identifier, signingShare: secrets[2] as Uint8Array },
    /** Copies of all three shares, for tests that sign outside the vaults. */
    clearShares: [share1, share2, agentShare].map((x, i) => ({
      identifier: x.identifier,
      signingShare: (secrets[i] as Uint8Array).slice(),
    })),
    holders,
    pub,
    secrets,
    get deal() {
      return deal;
    },
    setDeal: (d: SealedDeal) => {
      deal = d;
    },
    approveState,
    phoneVault,
    secondVault,
    phoneHolder,
    secondHolder,
    finished,
    record: p.record,
  };
}
