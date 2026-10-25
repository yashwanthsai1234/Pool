"""Random-cross mode: reads one JSON request per stdin line, writes one JSON reply per line. Used by tools/differential.

Request: {"op": "ref", "cases": [{"fn": ..., "args": {...hex strings...}}]}  or  {"op": "xrpl", "cases": [tx, ...]}
Reply:   {"results": [...]}. A case the reference refuses gives "ERR". Hashes are lowercase hex; ledger fields
(condition, URI, memo data) are uppercase hex, as DESIGN 6 says they appear on the ledger.
"""
import json
import sys

import legx_ref as L

H = bytes.fromhex
UP = {"walletAddress", "idMethodA", "idMethodB", "identityPolicy", "lawyerOpsA", "lawyerOpsB", "releaserAccount",
      "payoutA", "payoutB", "signerAccounts", "quorum"}
# TypeScript (PublicDealData) field names to the reference's names.
RENAME = {"commitmentA": "C_A", "commitmentB": "C_B", "lawyerCommitmentA": "LC_A", "lawyerCommitmentB": "LC_B"}


def seal_input(f: dict) -> dict:
    out = {}
    for k, v in f.items():
        out[RENAME.get(k, k)] = v if k in UP else H(v)
    return out


def memo(m: dict) -> str:
    return m["MemoType"] + ":" + m["MemoData"]


def ref(fn: str, a: dict) -> str:
    match fn:
        case "tupleHash":
            return L.tuple_hash(a["tag"], [H(p) for p in a["parts"]]).hex()
        case "dealSeal":
            return L.deal_seal(seal_input(a["fields"])).hex()
        case "domain":
            return L.domain(H(a["root"]), H(a["seal"])).hex().upper()
        case "contractRoot":
            return L.contract_root([H(s) for s in a["salts"]], [H(c) for c in a["clauses"]]).hex()
        case "bindMsg":
            return L.bind_msg(H(a["root"]), H(a["C"]), H(a["slotPub"]), a["side"]).hex()
        case "contractSigMsg":
            return L.contract_sig_msg(H(a["root"]), a["wallet"], a["role"]).hex()
        case "signedContractSeal":
            return L.signed_contract_seal(H(a["root"]), a["wallet"], H(a["pubA"]), H(a["sigLA"]), H(a["pubB"]),
                                          H(a["sigLB"])).hex()
        case "nftUri":
            return L.nft_uri(H(a["seal"]))
        case "mintMemo":
            return memo(L.mint_memo(H(a["pubA"]), H(a["sigLA"]), H(a["pubB"]), H(a["sigLB"])))
        case "opsBindMsg":
            return L.ops_bind_msg(H(a["root"]), a["ops"], H(a["lawyerPub"]), H(a["lc"]), a["role"]).hex()
        case "presenceMsg":
            return L.presence_msg(H(a["seal"]), a["side"], H(a["ledgerHash"]), H(a["nonce"])).hex()
        case "pqKeyHash":
            return L.pq_key_hash([H(p) for p in a["pubs"]]).hex()
        case "pqBindMsg":
            return L.pq_bind_msg(H(a["seal"]), H(a["slotPub"]), H(a["keyHash"])).hex()
        case "slotPolicy":
            return L.slot_policy(a["slot"], a["roles"]).hex()
        case "zk":
            return L.zk_commitment(H(a["salt"]), a["N"]).hex()
        case "condition":
            p = H(a["preimage"])
            return L.condition(p).hex().upper() + ":" + L.fulfillment(p).hex().upper()
        case "gateMemo":
            return memo(L.gate_memo(H(a["envelope"])))
        case "mu":
            return L.mldsa_mu(H(a["pub"]), H(a["ctx"]), H(a["msg"])).hex()
    raise ValueError(fn)


def xrpl(tx: dict) -> dict:
    from xrpl.core.binarycodec import encode, encode_for_multisigning, encode_for_signing

    out = {"encode": encode(tx), "signing": encode_for_signing(tx)}
    out["multisign"] = encode_for_multisigning(tx, tx["Account"])
    return out


def one(op: str, case):
    try:
        return ref(case["fn"], case["args"]) if op == "ref" else xrpl(case)
    except Exception:
        return "ERR"


for line in sys.stdin:
    req = json.loads(line)
    sys.stdout.write(json.dumps({"results": [one(req["op"], c) for c in req["cases"]]}) + "\n")
    sys.stdout.flush()
