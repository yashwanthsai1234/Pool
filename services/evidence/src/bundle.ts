// Module `bundle` (DESIGN 8.8): the evidence bundle for an arbitrator, a deterministic ZIP with the thirteen items of
// the design. Two builds from the same database state give the same bytes: files are the stored bytes or canonical JSON
// (RFC 8785), nothing carries a build time, the ZIP is fixed (see zip.ts), and the manifest signature is made once and
// kept in the WORM store (ML-DSA signing is randomized, so signing again would change the bytes).
//
//  1 manifest.json + manifest.dsse.json        7 keys/                      13 fre902/
//  2 contract/                                 8 signed-contract/            checks/report.json (what we verified)
//  3 events/                                   9 ops/ bar/
//  4 tlog/                                    10 attestations/ release/ zk/
//  5 anchors/                                 11 frost/ pq/
//  6 timestamps/                              12 verify.ts README.txt
// Source: DESIGN.md 8.8; https://github.com/secure-systems-lab/dsse/blob/master/protocol.md (manifest envelope)
// Source: https://github.com/C2SP/C2SP/blob/main/tlog-proof.md (tlog-proof files)
// Source: https://www.rfc-editor.org/rfc/rfc3161 (time-stamp tokens and their chains)
import type {
  ClockPort,
  LedgerPort,
  MlDsaContext,
  ObjectStorePort,
  SignerPort,
  TransparencyLogPort,
} from '@legx/contracts/ports';
import type { XrplHash } from '@legx/contracts/values';
import { type Envelope, pae } from '@legx/core/evidence';
import { toBase64 } from '@legx/core/pq';
import type { CheckpointKeys } from '@legx/core/pqCheckpoint';
import { vkey } from '@legx/core/pqCheckpoint';
import type { Database } from '@legx/db';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { tsaKey } from './anchor.ts';
import { canonicalBytes, parseEnvelope } from './events.ts';
import { checkpointKey, putWorm } from './log.ts';
import { rootFromInclusion, tlogProof } from './proofs.ts';
import { checkDealRecords, type RecordsDeps } from './records.ts';
import { verifyTimestampToken } from './tsa.ts';
import { type ZipFile, zip } from './zip.ts';

const utf8 = new TextEncoder();
const hexToBytes = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const six = (n: number) => String(n).padStart(6, '0');

/** The ML-DSA context of every DSSE signature (DESIGN 6.13). */
const DSSE_CONTEXT = 'legx/dsse/v1' satisfies MlDsaContext;
export const MANIFEST_TYPE = 'application/vnd.legx.manifest+json;v=1';

export interface LedgerServer {
  readonly name: string;
  readonly ledger: LedgerPort;
}

export interface BundleDeps {
  readonly db: Database;
  readonly log: TransparencyLogPort;
  readonly objects: ObjectStorePort;
  /** The service's hybrid signer (the manifest envelope). The PAE it signs is small: the manifest is a subject digest. */
  readonly signer: SignerPort;
  readonly clock: ClockPort;
  readonly retainDays: number;
  readonly origin: string;
  readonly checkpointKeys: CheckpointKeys;
  /** Two independent servers for the raw anchor transaction JSON (DESIGN 8.8 item 5). */
  readonly ledgers: readonly LedgerServer[];
  /** Time-stamp authorities whose tokens go in, and the roots that vouch for them. */
  readonly authorities: readonly string[];
  readonly trustedRoots: readonly Uint8Array[];
  readonly registry: RecordsDeps['registry'];
  /** The text of `assets/verify.ts` and of the plain README, read once by the composition. */
  readonly verifyScript: string;
  /** Runs first (the composition anchors a fresh checkpoint here), so the bundle covers every event. */
  readonly beforeBuild?: () => Promise<void>;
}

export interface BuiltBundle {
  readonly bytes: Uint8Array;
  readonly sha256: string;
  readonly filename: string;
}

/** Plain JSON for a database row: bytes as base64, dates as ISO text, RFC 8785 order. Never re-serializes an envelope. */
function normalize(v: unknown): unknown {
  if (v instanceof Uint8Array) return Buffer.from(v).toString('base64');
  if (v instanceof Date) return v.toISOString();
  if (typeof v === 'bigint') return v.toString();
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, normalize(x)]));
  return v;
}
export const jsonBytes = (v: unknown): Uint8Array => canonicalBytes(normalize(v));

const certPem = (der: Uint8Array) =>
  `-----BEGIN CERTIFICATE-----\n${Buffer.from(der)
    .toString('base64')
    .replace(/(.{64})/g, '$1\n')
    .trimEnd()}\n-----END CERTIFICATE-----\n`;

const README = `LEGX EVIDENCE BUNDLE

This ZIP holds the evidence of one deal. Everything in it can be checked without the service:

  node verify.ts .        (run in the unzipped folder; needs Node 24 or later; it makes no network calls)

What is in it
  manifest.json, manifest.dsse.json  SHA-256 of every file, and the service's signature over the manifest
  contract/                          the contract root and the file hashes
  events/                            every DSSE event of the deal, exactly as stored, in order
  tlog/                              a tlog-proof per event, the checkpoint, and a consistency proof
  anchors/                           the anchor transaction as two independent servers report it
  timestamps/                        RFC 3161 tokens and the authorities' certificate chains
  keys/                              public keys, binding statements and the key history
  signed-contract/, ops/, bar/       the signed contract, operations bindings, bar records
  attestations/, release/, zk/       passport attestations, the release gate, zero-knowledge proofs
  frost/, pq/                        FROST records and post-quantum bindings
  checks/report.json                 what the service itself verified when it built this bundle
  fre902/                            a certification template (US Federal Rule of Evidence 902(13) and 902(14))

An event is valid if both of its signatures verify (Ed25519 and ML-DSA-65), its seq and prev_hash continue the chain,
its inclusion proof leads to the signed checkpoint, and the checkpoint's root is the one the ledger anchor carries.
`;

const FRE902 = `CERTIFICATION OF A QUALIFIED PERSON (TEMPLATE)
US Federal Rules of Evidence 902(13) and 902(14). Arbitral bodies set their own evidence rules; treat this as persuasive.

I, [NAME], certify that:
1. I am [ROLE] and I am qualified to make this certification.
2. The electronic records in the file [BUNDLE FILE NAME], SHA-256 [HASH OF THE ZIP], were generated by an electronic
   process or system that produces an accurate result, as shown by the signed manifest (manifest.json, manifest.dsse.json)
   and the check report (checks/report.json).
3. The records are copies of data from an electronic device, storage medium or file. They were identified by the hash
   values in manifest.json, and each hash was recomputed by me on [DATE] with [TOOL AND VERSION], with the same result.
4. The records were made at or near the time of the events they record, by the parties and services named in each event,
   and were kept in the course of the regularly conducted activity of [SERVICE OPERATOR].

[SIGNATURE] [DATE] [PLACE]
`;

/** The bundle's file list, ready to zip. Exported for tests; `buildBundle` zips and returns it. */
export async function collectBundle(
  deps: BundleDeps,
  dealId: string,
  opts: { contractFiles?: Readonly<Record<string, Uint8Array>> } = {},
): Promise<ZipFile[]> {
  await deps.beforeBuild?.();
  const { db, objects } = deps;
  const files = new Map<string, Uint8Array>();
  const put = (path: string, bytes: Uint8Array) => {
    files.set(path, bytes);
  };
  const putJson = (path: string, v: unknown) => put(path, jsonBytes(v));

  const deal = await db.repos.deals.get(dealId);
  if (!deal) throw new Error(`unknown deal ${dealId}`);
  const rows = await db.repos.evidenceEvents.listAfter(dealId, -1, 100_000);
  const parsed = rows.map((r) => parseEnvelope(r.envelope));

  // 2. the contract: root, seals and any file hashes the party chose to include
  putJson('contract/contract.json', {
    contract_root: deal.contract_root,
    deal_seal: deal.deal_seal,
    signed_contract_seal: deal.signed_contract_seal,
    files: Object.fromEntries(Object.entries(opts.contractFiles ?? {}).map(([n, b]) => [n, bytesToHex(sha256(b))])),
  });
  for (const [name, bytes] of Object.entries(opts.contractFiles ?? {})) put(`contract/files/${name}`, bytes);

  // 3. every event, exactly as stored
  for (const r of rows) put(`events/${six(r.seq)}.dsse.json`, r.envelope);

  // 4. tlog-proof per event and a consistency proof, against the latest checkpoint
  const latest = await db.repos.checkpointAnchors.latest();
  const proofs: { seq: number; included: boolean }[] = [];
  if (latest) {
    const note = new TextDecoder().decode(latest.checkpoint);
    put('tlog/checkpoint.txt', latest.checkpoint);
    let last: { index: number; envelope: Uint8Array } | undefined;
    for (const r of rows) {
      const index = await db.repos.evidenceLogEntries.get(r.event_id);
      const included = index !== undefined && index < latest.tree_size;
      proofs.push({ seq: r.seq, included });
      if (!included) continue;
      const path = (await deps.log.inclusionProof(index, latest.tree_size)).map(hexToBytes);
      put(`tlog/proofs/${six(r.seq)}.tlog-proof`, utf8.encode(tlogProof(index, path, note)));
      if (!last || index > last.index) last = { index, envelope: r.envelope };
    }
    if (last) {
      const fromSize = last.index + 1;
      const fromPath = (await deps.log.inclusionProof(last.index, fromSize)).map(hexToBytes);
      const fromRoot = rootFromInclusion(last.envelope, last.index, fromSize, fromPath);
      putJson('tlog/consistency.json', {
        from_size: fromSize,
        from_root: fromRoot && bytesToHex(fromRoot),
        to_size: latest.tree_size,
        to_root: latest.root,
        path: await deps.log.consistencyProof(fromSize, latest.tree_size),
      });
    }
  }

  // 5. the anchor, as two independent servers report it
  if (latest) {
    putJson('anchors/anchor.json', {
      tree_size: latest.tree_size,
      root: latest.root,
      anchored: latest.anchor_tx_hash !== null,
      tx_hash: latest.anchor_tx_hash,
      ledger_index: latest.anchor_ledger,
    });
    if (latest.anchor_tx_hash && latest.anchor_ledger !== null) {
      for (const s of deps.ledgers) {
        putJson(`anchors/${s.name}.json`, await readAnchor(s, latest.anchor_tx_hash as XrplHash, latest.anchor_ledger));
      }
    }
  }

  // 6. RFC 3161 tokens and the authorities' chains
  const stamps: { authority: string; ok: boolean; code?: string; genTime?: string }[] = [];
  if (latest) {
    const note = await objects.get(checkpointKey(latest.tree_size, latest.root));
    for (const name of deps.authorities) {
      const token = await objects.get(tsaKey(latest.tree_size, latest.root, name));
      if (!token || !note) continue;
      put(`timestamps/${name}.tst`, token);
      const v = await verifyTimestampToken(token, sha256(note), deps.trustedRoots);
      stamps.push(
        v.ok
          ? { authority: name, ok: true, genTime: v.genTime.toISOString() }
          : { authority: name, ok: false, code: v.code },
      );
      if (v.ok) put(`timestamps/${name}.chain.pem`, utf8.encode(v.certificates.map(certPem).join('')));
    }
    put('timestamps/roots.pem', utf8.encode(deps.trustedRoots.map(certPem).join('')));
  }
  putJson('timestamps/status.json', { pending: stamps.every((s) => !s.ok), tokens: stamps });

  // 7. public keys, binding statements, key history
  const enrollment = await db.repos.enrollmentKeys.listForDeal(dealId);
  const dealKeys = await db.repos.dealKeys.list(dealId);
  const service = await deps.signer.publicKeys();
  putJson('keys/enrollment_keys.json', enrollment);
  putJson('keys/deal_keys.json', dealKeys);
  putJson('keys/service_keys.json', {
    ed25519: { key_id: service.keyIds.ed25519, public_key: bytesToHex(service.ed25519) },
    'ml-dsa-65': { key_id: service.keyIds.mlDsa65, public_key: toBase64(service.mlDsa65) },
  });
  putJson('keys/checkpoint_keys.json', {
    origin: deps.origin,
    ed: {
      name: deps.checkpointKeys.ed.name,
      public_key: bytesToHex(deps.checkpointKeys.ed.publicKey),
      vkey: vkey(deps.checkpointKeys.ed.name, 0x01, deps.checkpointKeys.ed.publicKey),
    },
    pq: {
      name: deps.checkpointKeys.pq.name,
      public_key: toBase64(deps.checkpointKeys.pq.publicKey),
      vkey: vkey(deps.checkpointKeys.pq.name, 0x06, deps.checkpointKeys.pq.publicKey),
    },
  });

  // 8. the signed contract: both contract signatures, the mint transaction and the NFT
  putJson('signed-contract/signed_contract.json', {
    contract_sigs: dealKeys
      .filter((k) => k.contract_sig)
      .map((k) => ({ role: k.role, lawyer_pub: k.xrpl_pubkey, contract_sig: k.contract_sig })),
    mint_tx_hash: deal.mint_tx_hash,
    nft_token_id: deal.nft_token_id,
    signed_contract_seal: deal.signed_contract_seal,
  });

  // 9. operations-account bindings, bar records, attorney credentials
  putJson(
    'ops/bindings.json',
    dealKeys
      .filter((k) => k.ops_account)
      .map((k) => ({
        role: k.role,
        ops_account: k.ops_account,
        lawyer_pub: k.xrpl_pubkey,
        sig_ops: k.ops_bind_sig_ops,
        sig_lawyer: k.ops_bind_sig_lawyer,
      })),
  );
  for (const l of await db.repos.barDealLinks.list(dealId))
    put(`bar/deal_links/${l.role}-${l.verification_sha256}.dsse.json`, l.envelope);
  for (const ops of [deal.lawyer_ops_a, deal.lawyer_ops_b].filter((x): x is string => !!x)) {
    for (const v of await db.repos.barVerifications.listFor(ops))
      put(`bar/verifications/${v.envelope_sha256}.dsse.json`, v.envelope);
    putJson(`bar/credentials/${ops}.json`, await db.repos.attorneyCredentials.listFor(ops));
  }

  // 10. passport attestations, the release gate and the validated EscrowFinish, zero-knowledge proofs
  for (const a of await db.repos.passportAttestations.list(dealId))
    put(`attestations/passport/${a.side}-${a.leaf_hash}.dsse.json`, a.envelope);
  for (const g of await db.repos.releaseGates.list(dealId)) put(`release/gate/${g.leaf_hash}.dsse.json`, g.envelope);
  const finish = parsed.find((e) => e.event.predicate.kind === 'release.performed')?.event.predicate.data as
    | { finish_tx_hash?: string }
    | undefined;
  if (finish?.finish_tx_hash) {
    for (const s of deps.ledgers)
      putJson(`release/finish.${s.name}.json`, await readTx(s, finish.finish_tx_hash as XrplHash));
  }
  const zk = await db.repos.zkProofs.list(dealId);
  for (const z of zk) putJson(`zk/proofs/${z.side}-${z.stage}.json`, z);
  putJson(
    'zk/trust_records.json',
    zk.map((z) => ({ side: z.side, stage: z.stage, registry_roots: z.registry_roots })),
  );

  // 11. FROST records and the post-quantum bindings: the events themselves, by kind
  const FROST = new Set(['frost.dkg.completed', 'frost.signed', 'frost.refreshed']);
  for (const [i, e] of parsed.entries()) {
    const kind = e.event.predicate.kind;
    const seq = (rows[i] as { seq: number }).seq;
    if (FROST.has(kind)) put(`frost/${six(seq)}-${kind}.dsse.json`, (rows[i] as { envelope: Uint8Array }).envelope);
    if (kind === 'pq.bound') put(`pq/${six(seq)}-${kind}.dsse.json`, (rows[i] as { envelope: Uint8Array }).envelope);
  }

  // checks: what this service verified (signature, chain, ledger) for every event, and by category
  const rd: RecordsDeps = {
    db,
    clock: deps.clock,
    ledger: (deps.ledgers[0] as LedgerServer).ledger,
    registry: deps.registry,
  };
  const { checks } = await checkDealRecords(rd, dealId);
  const byKind = (pred: (kind: string) => boolean) =>
    parsed.flatMap((e, i) =>
      pred(e.event.predicate.kind)
        ? [{ seq: (rows[i] as { seq: number }).seq, kind: e.event.predicate.kind, ...(checks[i] as object) }]
        : [],
    );
  putJson('checks/report.json', {
    deal_id: dealId,
    events: checks.map((c, i) => ({
      ...c,
      kind: parsed[i]?.event.predicate.kind,
      in_checkpoint: proofs[i]?.included ?? false,
    })),
    categories: {
      frost: byKind((k) => FROST.has(k)),
      pq_bindings: byKind((k) => k === 'pq.bound'),
      identity: byKind((k) => k === 'identity.onboarded' || k === 'passport.verified'),
      release_gate: byKind((k) => k === 'release.gate.passed' || k === 'release.performed'),
      zero_knowledge: zk.map((z) => ({
        side: z.side,
        stage: z.stage,
        has_registry_roots: z.registry_roots !== undefined,
      })),
    },
    timestamps: stamps,
  });

  // 12 and 13
  put('verify.ts', utf8.encode(deps.verifyScript));
  put('README.txt', utf8.encode(README));
  put('fre902/certification-template.txt', utf8.encode(FRE902));

  // 1. the manifest: every file's SHA-256, then a DSSE envelope over a subject digest of the manifest
  const list = [...files.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  const manifest = jsonBytes({
    deal_id: dealId,
    files: list.map(([path, bytes]) => ({ path, sha256: bytesToHex(sha256(bytes)), size: bytes.length })),
  });
  put('manifest.json', manifest);
  put('manifest.dsse.json', await sealManifest(deps, dealId, manifest));
  return [...files.entries()].map(([path, bytes]) => ({ path, bytes }));
}

export async function buildBundle(
  deps: BundleDeps,
  dealId: string,
  opts: { contractFiles?: Readonly<Record<string, Uint8Array>> } = {},
): Promise<BuiltBundle> {
  const bytes = zip(await collectBundle(deps, dealId, opts));
  const digest = bytesToHex(sha256(bytes));
  return { bytes, sha256: digest, filename: `legx-evidence-${dealId}.zip` };
}

/**
 * The DSSE envelope over `{subject: manifest.json digest}`. ML-DSA signatures are randomized, so the first envelope for
 * a manifest is kept in the WORM store and every later build reuses it: the same manifest always gives the same bytes.
 */
async function sealManifest(deps: BundleDeps, dealId: string, manifest: Uint8Array): Promise<Uint8Array> {
  const digest = bytesToHex(sha256(manifest));
  const key = `bundles/${dealId}/${digest}.dsse.json`;
  const kept = await deps.objects.get(key);
  if (kept) return kept;
  const statement = canonicalBytes({
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'manifest.json', digest: { sha256: digest } }],
    predicateType: 'https://legx.dev/bundle-manifest/v1',
    predicate: { deal_id: dealId, sig_algs: ['ed25519', 'ml-dsa-65'] },
  });
  const sig = await deps.signer.signHybrid(pae(MANIFEST_TYPE, statement), DSSE_CONTEXT);
  const env: Envelope = {
    payloadType: MANIFEST_TYPE,
    payload: toBase64(statement),
    signatures: [
      { keyid: sig.keyIds.ed25519, sig: toBase64(sig.ed25519) },
      { keyid: sig.keyIds.mlDsa65, sig: toBase64(sig.mlDsa65) },
    ],
  };
  const bytes = canonicalBytes(env);
  await putWorm(deps.objects, key, bytes, deps.retainDays);
  return (await deps.objects.get(key)) ?? bytes; // a concurrent builder may have stored its own first
}

async function readTx(s: LedgerServer, hash: XrplHash) {
  try {
    const tx = await s.ledger.tx(hash);
    return tx ? { server: s.name, found: true, tx } : { server: s.name, found: false };
  } catch (e) {
    return { server: s.name, found: false, error: (e as Error).message };
  }
}

async function readAnchor(s: LedgerServer, hash: XrplHash, ledgerIndex: number) {
  const tx = await readTx(s, hash);
  try {
    return { ...tx, ledger: await s.ledger.ledgerHeader(ledgerIndex) };
  } catch (e) {
    return { ...tx, ledger_error: (e as Error).message };
  }
}
