// Vendored from ZKPassport's headless prover, a development tool only (never shipped).
// Source: https://github.com/zkpassport/zkpassport-packages/blob/a61b0cf461f1fab10e1b838dacd81e862107acb0/packages/e2e/src/prove.ts
// Upstream commit a61b0cf461f1fab10e1b838dacd81e862107acb0 (23 Oct 2026), matching @zkpassport/sdk 0.19.2,
// @zkpassport/utils 0.40.0-beta.2 and @zkpassport/registry 0.15.3. Licensed under the Apache License 2.0 (see
// ./LICENSE, copied from packages/zkpassport-sdk/LICENSE of the same commit; packages/e2e names no other licence).
// Changes by legx (Apache-2.0 section 4b), each marked "legx:" below:
//   1. `bind` (the bind circuit) and `expiry_date` gt/gte (the compare_expiry circuit) are proven;
//   2. `disclose` is accepted for firstname, lastname, birthdate and nationality (one disclose_bytes proof);
//   3. an optional `now` (unix seconds) replaces the clock, so a fixture can prove at a past date;
//   4. `facematch` is accepted but not proven: a face match needs the app's attestation, which no headless
//      prover has, so verify() reports the missing face match (a recorded failure case);
//   5. one type assertion for this repository's TypeScript settings (no behaviour change).
import { createHash } from 'node:crypto';
import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import { type CompiledCircuit, type InputMap, Noir } from '@noir-lang/noir_js';
import type { RegistryClient } from '@zkpassport/registry';
import {
  AsyncOrderedMT,
  extractTBS,
  getAgeCircuitInputs,
  getBindCircuitInputs,
  getBitSize,
  getCscaForPassportAsync,
  getDiscloseCircuitInputs,
  getDSCCircuitInputs,
  getDSCSignatureAlgorithmHashAlgorithm,
  getECDSAInfo,
  getExpiryDateCircuitInputs,
  getIDDataCircuitInputs,
  getIntegrityCheckCircuitInputs,
  getRSAInfo,
  getSanctionsExclusionCheckCircuitInputs,
  getServiceScopeHash,
  getServiceSubscopeHash,
  getSodSignatureAlgorithmHashAlgorithm,
  getSodSignatureAlgorithmType,
  getTBSMaxLen,
  type PackagedCertificate,
  type PackagedCertificatesFile,
  type PassportViewModel,
  type ProofResult,
  poseidon2,
  type Query,
  type QueryResult,
  SanctionsBuilder,
  TargetExistsError,
} from '@zkpassport/utils';

/** legx: the fields one disclose_bytes proof discloses */
const DISCLOSABLE = ['firstname', 'lastname', 'birthdate', 'nationality'] as const;

const SALT = BigInt('0x' + '11'.repeat(31));

type ProofStep = { name: string; inputs: object; committedInputs?: unknown };

export type ProvingOverrides = {
  /** Packaged certificates to prove against instead of those for the registry's latest root */
  certificates?: PackagedCertificatesFile;
};

export async function proveFastMode({
  passport,
  query,
  domain,
  scope,
  circuitVersion,
  registry,
  overrides = {},
  now = Math.floor(Date.now() / 1000),
}: {
  passport: PassportViewModel;
  query: Query;
  domain: string;
  scope?: string;
  circuitVersion: string;
  registry: RegistryClient;
  overrides?: ProvingOverrides;
  /** legx: the proving time in unix seconds */
  now?: number;
}): Promise<{ proofs: ProofResult[]; queryResult: QueryResult }> {
  // legx: bind, expiry_date and the disclosed name and birthdate fields
  const disclosed = DISCLOSABLE.filter((field) => query[field]);
  const unhandled = Object.keys(query).filter(
    (field) => !['age', 'sanctions', 'bind', 'expiry_date', 'facematch', ...DISCLOSABLE].includes(field),
  );
  if (
    unhandled.length > 0 ||
    (query.age && !query.age.gte) ||
    (query.expiry_date && !query.expiry_date.gt && !query.expiry_date.gte) ||
    disclosed.some((field) => !query[field]?.disclose)
  ) {
    throw new Error(
      `Only age.gte, expiry_date.gt/gte, bind, sanctions and disclose are handled, got ${JSON.stringify(query)}`,
    );
  }

  const packagedCerts = overrides.certificates ?? (await registry.getCertificates());
  const manifest = await registry.getCircuitManifest(undefined, { version: circuitVersion });
  const names = await getBaseCircuitNames(passport, packagedCerts.certificates);

  const salts = getIntegrityToDisclosureSalts(SALT);
  const disclosureArgs = [
    salts,
    0n,
    getServiceScopeHash(domain),
    getServiceSubscopeHash(scope as string),
    now, // legx: was Math.floor(Date.now() / 1000)
  ] as const;

  const steps: ProofStep[] = [
    {
      name: names.dsc,
      inputs: required(await getDSCCircuitInputs(passport, SALT, packagedCerts), names.dsc),
    },
    {
      name: names.idData,
      inputs: required(await getIDDataCircuitInputs(passport, SALT, SALT), names.idData),
    },
    {
      name: names.integrity,
      inputs: required(await getIntegrityCheckCircuitInputs(passport, SALT, salts), names.integrity),
    },
  ];

  // Committed inputs as the app's DisclosureProofService records them
  if (query.age) {
    const inputs = required(await getAgeCircuitInputs(passport, query, ...disclosureArgs), 'compare_age');
    steps.push({
      name: 'compare_age',
      inputs,
      committedInputs: { minAge: inputs.min_age_required, maxAge: inputs.max_age_required },
    });
  }
  // legx: the expiry check, committed the way the SDK reads it (getMinDateFromCommittedInputs)
  if (query.expiry_date) {
    const inputs = required(await getExpiryDateCircuitInputs(passport, query, ...disclosureArgs), 'compare_expiry');
    steps.push({
      name: 'compare_expiry',
      inputs,
      committedInputs: { minDateTimestamp: inputs.min_date, maxDateTimestamp: inputs.max_date },
    });
  }
  // legx: the bound data, committed as the SDK's bind check reads it
  if (query.bind) {
    const inputs = required(await getBindCircuitInputs(passport, query, ...disclosureArgs), 'bind');
    steps.push({ name: 'bind', inputs, committedInputs: { data: query.bind } });
  }
  if (disclosed.length > 0) {
    const inputs = required(await getDiscloseCircuitInputs(passport, query, ...disclosureArgs), 'disclose_bytes');
    const dg1 = inputs.salted_dg1.value as number[];
    steps.push({
      name: 'disclose_bytes',
      inputs,
      committedInputs: {
        // legx: `as number` for our noUncheckedIndexedAccess setting (type only)
        disclosedBytes: dg1.slice(5).map((byte, index) => byte * (inputs.disclose_mask[index] as number)),
        discloseMask: inputs.disclose_mask,
      },
    });
  }
  if (query.sanctions) {
    const inputs = required(
      await getSanctionsExclusionCheckCircuitInputs(
        passport,
        query.sanctions.strict ?? false,
        ...disclosureArgs,
        undefined,
        await getSanctionsBuilder(registry),
      ).catch(toSanctionsCheckFailed),
      'exclusion_check_sanctions',
    );
    steps.push({
      name: 'exclusion_check_sanctions',
      inputs,
      committedInputs: { rootHash: inputs.root, isStrict: !!inputs.is_strict },
    });
  }

  const barretenberg = await startBarretenberg();
  const proofs: ProofResult[] = [];
  try {
    for (const [index, step] of steps.entries()) {
      const circuit = await registry.getPackagedCircuit(step.name, manifest);
      // Packaged circuits carry no debug symbols
      const noir = new Noir({
        bytecode: circuit.bytecode,
        abi: circuit.abi as CompiledCircuit['abi'],
        debug_symbols: '',
        file_map: {},
      });
      const { witness } = await noir.execute(step.inputs as InputMap);
      const { proof, publicInputs } = await new UltraHonkBackend(circuit.bytecode, barretenberg).generateProof(witness);

      proofs.push({
        // Same layout as the app's generateProof(): [public inputs][proof body], hex, no 0x
        proof:
          publicInputs.map((input) => input.replace(/^0x/, '').padStart(64, '0')).join('') +
          Buffer.from(proof).toString('hex'),
        vkeyHash: circuit.vkey_hash,
        version: manifest.version as ProofResult['version'],
        name: circuit.name,
        index,
        total: steps.length,
        ...(step.committedInputs ? { committedInputs: { [circuit.name]: step.committedInputs } } : {}),
      } as ProofResult);
    }
  } finally {
    await barretenberg.destroy();
  }

  return { proofs, queryResult: getQueryResult(passport, query) };
}

/** The passport is on a sanctions list, so no exclusion proof exists for it */
export class SanctionsCheckFailedError extends Error {}

/**
 * A Barretenberg whose native prover accepted its connection. bb.js gives the prover 5 seconds to
 * start, which a slow CI runner's first start can miss, and reports the miss only at the first call,
 * so connect here and start again on that timeout.
 */
async function startBarretenberg(attempts = 3): Promise<Barretenberg> {
  for (let attempt = 1; ; attempt++) {
    const barretenberg = await Barretenberg.new();
    try {
      await barretenberg.blake2s({ data: new Uint8Array() });
      return barretenberg;
    } catch (error) {
      await barretenberg.destroy().catch(() => {});
      if (attempt >= attempts || !/Timeout (waiting for bb|connecting to bb)/.test(String(error))) {
        throw error;
      }
    }
  }
}

/** The sanctions tree published for the latest sanctions root of the registry's chain */
async function getSanctionsBuilder(registry: RegistryClient): Promise<SanctionsBuilder> {
  const { serialised } = await registry.getSanctionsTree();
  return new SanctionsBuilder(await AsyncOrderedMT.fromSerialized(serialised, poseidon2));
}

/** A failed exclusion proof read the way the app's circuit-matcher.ts reads it */
function toSanctionsCheckFailed(error: unknown): never {
  if (error instanceof TargetExistsError) {
    throw new SanctionsCheckFailedError();
  }
  throw error;
}

/** A curve as circuit names spell it, the way the app's circuit-matcher.ts does: nist_p256 */
function curveId(curve: string): string {
  const family = curve.includes('brainpool') ? 'brainpool' : 'nist';
  const name = curve.replace('brainpoolP', '').replace('nist', '').replace('-', '').toLowerCase();
  return `${family}_${name}`;
}

/** Inputs from a @zkpassport/utils builder, which returns null or undefined when it cannot build them */
function required<T extends object>(inputs: T | null | undefined, circuitName: string): T {
  if (!inputs) {
    throw new Error(`Could not build the inputs of ${circuitName}`);
  }
  return inputs;
}

/** What the app's getPassportFieldsFromQuery() reports for a query this headless app proves */
function getQueryResult(passport: PassportViewModel, query: Query): QueryResult {
  const result: Record<string, unknown> = {};
  if (query.age) {
    result.age = { gte: { expected: query.age.gte as number, result: true } };
  }
  // legx: every disclosed field, as the app reports it
  if (query.firstname) result.firstname = { disclose: { result: passport.firstName } };
  if (query.lastname) result.lastname = { disclose: { result: passport.lastName } };
  if (query.birthdate) result.birthdate = { disclose: { result: birthDate(passport.dateOfBirth) } };
  if (query.nationality) {
    result.nationality = { disclose: { result: passport.nationality } };
  }
  if (query.expiry_date)
    result.expiry_date = query.expiry_date.gt
      ? { gt: { expected: query.expiry_date.gt as Date, result: true } }
      : { gte: { expected: query.expiry_date.gte as Date, result: true } };
  if (query.bind) result.bind = query.bind;
  if (query.sanctions) {
    // Proving succeeded, so the passport is not on the lists
    const passed = { passed: true };
    result.sanctions = {
      passed: true,
      countries: { US: passed, GB: passed, EU: passed, CH: passed },
      lists: {
        US_OFAC_SDN: passed,
        CH_SECO_SANCTIONS: passed,
        EU_FSF_SANCTIONS: passed,
        GB_FCDO_SANCTIONS: passed,
      },
      isStrict: query.sanctions.strict ?? false,
    };
  }
  return result as QueryResult;
}

// Copied from zkpassport-mobile-app src/lib/index.ts
function getPublicSalt(salt: bigint): bigint {
  const saltBytes = Buffer.from(salt.toString(16), 'hex');
  return BigInt('0x' + createHash('sha256').update(saltBytes).digest('hex'));
}

// Copied from zkpassport-mobile-app src/lib/index.ts
function getIntegrityToDisclosureSalts(salt: bigint) {
  const publicSalt = getPublicSalt(salt);
  return {
    dg1Salt: salt,
    dg2HashSalt: publicSalt,
    expiryDateSalt: publicSalt,
    privateNullifierSalt: salt,
  };
}

/**
 * The DSC, ID data and integrity circuit names for a passport, as zkpassport-mobile-app's
 * getDSCCircuit, getIDDataCircuit and getIntegrityCheckCircuit build them; RSA PKCS only
 */
async function getBaseCircuitNames(passport: PassportViewModel, certificates: PackagedCertificate[]) {
  const tbsMaxLen = getTBSMaxLen(passport);
  const csca = await getCscaForPassportAsync(passport.sod.certificate, certificates);
  if (!csca) {
    throw new Error("No CSCA found for the passport's DSC in the certificate registry");
  }
  const cscaKey =
    csca.public_key.type === 'EC'
      ? `ecdsa_${curveId(csca.public_key.curve)}`
      : `rsa_${csca.signature_algorithm === 'RSA-PSS' ? 'pss' : 'pkcs'}_${getBitSize(BigInt(csca.public_key.modulus))}`;
  const dsc = `sig_check_dsc_tbs_${tbsMaxLen}_${cscaKey}_${getDSCSignatureAlgorithmHashAlgorithm(passport)}`;

  const tbs = extractTBS(passport);
  if (!tbs) {
    throw new Error('Could not extract the DSC TBS');
  }
  const idScheme = passport.sod.signerInfo.signatureAlgorithm.name.toLowerCase().includes('pss') ? 'pss' : 'pkcs';
  const dscKey =
    getSodSignatureAlgorithmType(passport) === 'ECDSA'
      ? `ecdsa_${curveId(getECDSAInfo(tbs.subjectPublicKeyInfo).curve)}`
      : `rsa_${idScheme}_${getBitSize(getRSAInfo(tbs.subjectPublicKeyInfo).modulus)}`;
  const idData = `sig_check_id_data_tbs_${tbsMaxLen}_${dscKey}_${getSodSignatureAlgorithmHashAlgorithm(passport)}`;

  const saHash = passport.sod.signerInfo.digestAlgorithm.toLowerCase().replace('-', '');
  const dgHash = passport.sod.encapContentInfo.eContent.hashAlgorithm.toLowerCase().replace('-', '');
  const integrity = `data_check_integrity_sa_${saHash}_dg_${dgHash}`;
  return { dsc, idData, integrity };
}

/** legx: an MRZ birth date (YYMMDD) as a UTC date; a two-digit year after this year is in the 1900s */
function birthDate(yymmdd: string): Date {
  const yy = Number(yymmdd.slice(0, 2));
  const century = yy > new Date().getUTCFullYear() % 100 ? 1900 : 2000;
  return new Date(Date.UTC(century + yy, Number(yymmdd.slice(2, 4)) - 1, Number(yymmdd.slice(4, 6))));
}
