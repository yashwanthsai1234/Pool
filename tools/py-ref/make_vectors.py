"""Builds fixed-input golden vectors (hex) into vectors/*.json. Run: uv run python make_vectors.py"""
import json
import pathlib

import legx_ref as L

B = lambda n, c=32: bytes([n]) * c  # noqa: E731
H = lambda b: b.hex()  # noqa: E731
P33 = lambda n: b"\xed" + B(n)  # noqa: E731


def seal_fields() -> dict:
    return {
        "contractRoot": B(1), "signedContractSeal": B(2), "walletAddress": "rWallet", "xPubA": P33(3),
        "xPubB": P33(4), "C_A": B(5), "C_B": B(6), "idMethodA": "zkpassport", "idMethodB": "nfc-chip",
        "identityPolicy": "zk-or-chip", "lawyerPubA": P33(7), "lawyerPubB": P33(8), "LC_A": B(9),
        "LC_B": B(10), "lawyerOpsA": "rOpsA", "lawyerOpsB": "rOpsB", "releaserAccount": "rOpsB",
        "slotPolicyA": B(11), "slotPolicyLA": B(12), "slotPolicyB": B(13), "slotPolicyLB": B(14),
        "pqKeyHashA": B(15), "pqKeyHashLA": B(16), "pqKeyHashB": B(17), "pqKeyHashLB": B(18),
        "signerAccounts": ["rD", "rB", "rA", "rC"], "quorum": 4, "payoutA": "rPayA:42", "payoutB": "rPayB",
    }


DEAL_ID = "0192f1a0-7b3c-7d4e-8f00-0000000000a1"
ITEMS = [
    {"sku": "SKU-1", "description": "Steel bolts, M8 \"zinc\"", "qty": 200, "weight_g": 1800},
    {"sku": "SKU-2", "description": "Caf\u00e9 cups \u20ac / \U0001F600\ttab", "qty": 12, "weight_g": 3600},
    {"sku": "SKU-3", "description": "", "qty": 1, "weight_g": 0},
]


def shipment_vectors(seal: bytes, v) -> list[dict]:
    out = [v("jcsItem", {"item": i}, H(L.jcs_item(i))) for i in ITEMS]
    out += [v("manifestRoot", {"items": ITEMS[:n]}, H(L.manifest_root(ITEMS[:n]))) for n in range(1, 4)]
    root = L.manifest_root(ITEMS)
    ship_in = {"dealId": DEAL_ID, "dealSeal": H(seal), "manifestRoot": H(root), "carrier": "DHL Express",
               "trackingId": "JD014600006281230704", "ledgerIndex": 90_000_050}
    sm = L.ship_msg(DEAL_ID, seal, root, "DHL Express", "JD014600006281230704", 90_000_050)
    out.append(v("shipMsg", ship_in, H(sm)))
    sh = L.sha(sm)
    for cond in L.CONDITIONS:
        rin = {"dealId": DEAL_ID, "dealSeal": H(seal), "shipmentHash": H(sh), "manifestRoot": H(root),
               "condition": cond, "ledgerIndex": 90_000_080}
        out.append(v(f"rcptMsg/{cond}", rin, H(L.rcpt_msg(DEAL_ID, seal, sh, root, cond, 90_000_080))))
    return out


def build() -> dict[str, list[dict]]:
    seal = L.deal_seal(seal_fields())
    s, c, k = B(0xAA), B(0xBB), [B(0x21, 1952), B(0x22, 1952), B(0x23, 1952)]
    sigs = (P33(7), B(0x31, 64), P33(8), B(0x32, 64))
    cs = L.signed_contract_seal(B(1), "rWallet", *sigs)
    clauses = ["Clause one\r\nline", "﻿Clé two", "three"]
    salts = [B(0x41), B(0x42), B(0x43)]
    cb = [L.clause_bytes(x) for x in clauses]
    v = lambda name, i, o: {"fn": name, "inputs": i, "output": o}  # noqa: E731
    return {
        "tuple_hash": [v("tupleHash", {"tag": "t", "parts": [H(b""), H(b"ab")]}, H(L.tuple_hash("t", [b"", b"ab"])))],
        "contract_root": [
            v("contractRoot", {"salts": [H(x) for x in salts[:n]], "clauses_hex": [H(x) for x in cb[:n]]},
              H(L.contract_root(salts[:n], cb[:n]))) for n in range(4)
        ] + [v("clauseBytes", {"text": clauses[1]}, H(cb[1]))],
        "identity": [
            v("zk", {"salt": H(s), "N": "id-123"}, H(L.zk_commitment(s, "id-123"))),
            v("chip", {"salt": H(s), "dg1": "aabb", "sod": "ccdd"}, H(L.chip_commitment(s, b"\xaa\xbb", b"\xcc\xdd"))),
            v("bar", {"salt": H(s), "jurisdiction": "US-CA", "bar": "123456"}, H(L.bar_commitment(s, "US-CA", "123456"))),
            v("distinctTag", {"dealId": "0192f1a0-7b3c-7d4e-8f00-0000000000a1", "x": H(L.sha(b"P<UTOSAME"))},
              H(L.distinct_tag("0192f1a0-7b3c-7d4e-8f00-0000000000a1", L.sha(b"P<UTOSAME")))),
        ],
        "slot_policy": [v("slotPolicy", {"slot": "A", "roles": L.CLIENT_ROLES}, H(L.slot_policy("A", L.CLIENT_ROLES))), v("slotPolicy", {"slot": "LA", "roles": L.LAWYER_ROLES}, H(L.slot_policy("LA", L.LAWYER_ROLES)))],
        "bind_msg": [v("bindMsg", {"root": H(B(1)), "C": H(c), "slotPub": H(P33(3)), "side": "A"}, H(L.bind_msg(B(1), c, P33(3), "A")))],
        "deal_seal": [
            v("dealSeal", {k: (H(x) if isinstance(x, bytes) else x) for k, x in seal_fields().items()}, H(seal)),
            v("domain", {"root": H(B(1)), "seal": H(seal)}, L.domain(B(1), seal).hex().upper()),
        ],
        "condition": [
            v("condition", {"preimage": H(B(0))}, H(L.condition(B(0)))),
            v("fulfillment", {"preimage": H(B(0))}, H(L.fulfillment(B(0)))),
            v("condition", {"preimage": H(B(7))}, H(L.condition(B(7)))),
        ],
        "signed_contract": [
            v("contractSigMsg", {"root": H(B(1)), "wallet": "rWallet", "role": "LA"}, H(L.contract_sig_msg(B(1), "rWallet", "LA"))),
            v("signedContractSeal", {"root": H(B(1)), "wallet": "rWallet", "pubA": H(sigs[0]), "sigLA": H(sigs[1]), "pubB": H(sigs[2]), "sigLB": H(sigs[3])}, H(cs)),
            v("nftUri", {"seal": H(cs)}, L.nft_uri(cs)),
            v("mintMemo", {"pubA": H(sigs[0]), "sigLA": H(sigs[1]), "pubB": H(sigs[2]), "sigLB": H(sigs[3])}, L.mint_memo(*sigs)),
        ],
        "pq": [
            v("pqKeyHash", {"pubs": [H(x) for x in k]}, H(L.pq_key_hash(k))),
            v("pqBindMsg", {"dealSeal": H(seal), "slotPub": H(P33(3)), "pqKeyHash": H(L.pq_key_hash(k))}, H(L.pq_bind_msg(seal, P33(3), L.pq_key_hash(k)))),
        ],
        "ops_bind": [v("opsBindMsg", {"root": H(B(1)), "ops": "rOpsA", "lawyerPub": H(P33(7)), "LC": H(B(9)), "role": "LA"}, H(L.ops_bind_msg(B(1), "rOpsA", P33(7), B(9), "LA")))],
        "presence": [v("presenceMsg", {"dealSeal": H(seal), "side": "B", "ledgerHash": H(B(0x51)), "nonce": H(B(0x52))}, H(L.presence_msg(seal, "B", B(0x51), B(0x52))))],
        "shipment": shipment_vectors(seal, v),
        "gate_memo": [v("gateMemo", {"envelope": H(b'{"payloadType":"x"}')}, L.gate_memo(b'{"payloadType":"x"}'))],
    }


if __name__ == "__main__":
    out = pathlib.Path(__file__).parent / "vectors"
    for name, vs in build().items():
        (out / f"{name}.json").write_text(json.dumps(vs, indent=1) + "\n")
