// E2E-P1: the independent Python reference (tools/py-ref/legx_ref.py, written from DESIGN alone) run on the paper
// deal's own inputs. Python 3 with the standard library only; `-I` ignores the environment and the working directory.
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

const REF_DIR = join(import.meta.dirname, '../../../../tools/py-ref');

const SCRIPT = `
import json, sys
sys.path.insert(0, ${JSON.stringify(REF_DIR)})
import legx_ref as L
x = json.load(sys.stdin)
B = bytes.fromhex
f = x['seal']
fields = {k: (v if isinstance(v, (str, int, list)) and k in ('walletAddress','idMethodA','idMethodB','identityPolicy','lawyerOpsA','lawyerOpsB','releaserAccount','payoutA','payoutB','signerAccounts','quorum') else B(v)) for k, v in f.items()}
seal = L.deal_seal(fields)
root = L.contract_root([B(s) for s in x['salts']], [L.clause_bytes(c) for c in x['clauses']])
sigs = (B(x['pubLA']), B(x['sigLA']), B(x['pubLB']), B(x['sigLB']))
csal = L.signed_contract_seal(root, x['wallet'], *sigs)
out = {
  'contractRoot': root.hex(),
  'dealSeal': seal.hex(),
  'domain': L.domain(root, seal).hex().upper(),
  'contractSigMsg': {r: L.contract_sig_msg(root, x['wallet'], r).hex() for r in ('LA', 'LB')},
  'signedContractSeal': csal.hex(),
  'nftUri': L.nft_uri(csal),
  'mintMemo': L.mint_memo(*sigs),
  'slotPolicy': {s: L.slot_policy(s, r).hex() for s, r in x['roles'].items()},
  'bindMsg': {s: L.bind_msg(root, B(c), B(x['slotPubs'][s]), s).hex() for s, c in x['commitments'].items()},
  'pqKeyHash': {s: L.pq_key_hash([B(p) for p in ps]).hex() for s, ps in x['pqPubs'].items()},
  'pqBindMsg': {s: L.pq_bind_msg(seal, B(x['slotPubs'][s]), L.pq_key_hash([B(p) for p in ps])).hex() for s, ps in x['pqPubs'].items()},
  'opsBindMsg': {r: L.ops_bind_msg(root, o['ops'], B(x['slotPubs'][r]), B(o['lc']), r).hex() for r, o in x['ops'].items()},
  'presenceMsg': {s: L.presence_msg(seal, s, B(p['ledgerHash']), B(p['nonce'])).hex() for s, p in x['presence'].items()},
  'zkCommitment': L.zk_commitment(B(x['zk']['salt']), x['zk']['N']).hex(),
  'chipCommitment': L.chip_commitment(B(x['chip']['salt']), B(x['chip']['dg1']), B(x['chip']['sod'])).hex(),
  'barCommitment': {r: L.bar_commitment(B(b['salt']), b['jurisdiction'], b['bar']).hex() for r, b in x['bar'].items()},
  'gateMemo': L.gate_memo(B(x['gateEnvelope'])),
}
json.dump(out, sys.stdout)
`;

/** Runs the Python reference on `input` (JSON) and returns its JSON output. */
export function pyRef<T = Record<string, unknown>>(input: unknown): T {
  const out = execFileSync('python3', ['-I', '-c', SCRIPT], { input: JSON.stringify(input), encoding: 'utf8' });
  return JSON.parse(out) as T;
}
