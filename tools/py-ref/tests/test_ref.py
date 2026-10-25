import json
import pathlib

import pytest

import legx_ref as L
from make_vectors import B, P33, build, seal_fields

VEC = pathlib.Path(__file__).parent.parent / "vectors"


def test_t_u_01_condition_known_vector():
    assert L.condition(B(0)).hex().upper() == "A025802066687AADF862BD776C8FC18B8E9F8E20089714856EE233B3902A591D0D5F2925810120"
    assert len(L.condition(B(0))) == 39 and L.fulfillment(B(0)) == bytes.fromhex("A0228020") + B(0)


def test_t_u_04_empty_tree_and_rfc9162_shape():
    assert L.merkle_root([]) == L.sha(b"")
    a, b, c = (bytes([i]) for i in (1, 2, 3))
    h = lambda x: L.sha(b"\x00" + x)  # noqa: E731
    n = lambda x, y: L.sha(b"\x01" + x + y)  # noqa: E731
    assert L.merkle_root([a, b, c]) == n(n(h(a), h(b)), h(c))


def test_sizes():
    assert len(L.domain(B(1), B(2))) == 65
    assert len(bytes.fromhex(L.nft_uri(B(1)))) == 75
    assert len(L.mint_memo(P33(1), B(2, 64), P33(3), B(4, 64))["MemoData"]) == 390
    assert len(SEAL := L.SEAL_FIELDS) == 29 and len(set(SEAL)) == 29


def test_signer_order_and_releaser_rule():
    f = seal_fields()
    g = dict(f, signerAccounts=list(reversed(f["signerAccounts"])))
    assert L.deal_seal(f) == L.deal_seal(g)
    with pytest.raises(ValueError):
        L.deal_seal(dict(f, releaserAccount="rOther"))


@pytest.mark.parametrize("name", [p.stem for p in sorted(VEC.glob("*.json"))])
def test_vectors_match_files(name):
    assert json.loads((VEC / f"{name}.json").read_text()) == json.loads(json.dumps(build()[name]))


def test_every_function_has_a_vector():
    fns = {x["fn"] for vs in build().values() for x in vs}
    assert fns >= {"tupleHash", "contractRoot", "clauseBytes", "zk", "chip", "bar", "slotPolicy", "bindMsg", "dealSeal",
                   "domain", "condition", "fulfillment", "contractSigMsg", "signedContractSeal", "nftUri", "mintMemo",
                   "pqKeyHash", "pqBindMsg", "opsBindMsg", "presenceMsg", "gateMemo", "distinctTag"}


def flip(b: bytes) -> bytes:
    return bytes([b[0] ^ 1]) + b[1:]


def test_each_of_29_seal_fields_changes_seal():
    f, base = seal_fields(), L.deal_seal(seal_fields())
    for k in L.SEAL_FIELDS:
        v = f[k]
        if isinstance(v, bytes):
            nv = flip(v)
        elif k == "quorum":
            nv = 3
        elif k == "signerAccounts":
            nv = v + ["rE"]
        else:
            nv = v + "x"
        g = dict(f, **{k: nv})
        if k in ("releaserAccount", "lawyerOpsB"):
            g["releaserAccount"] = g["lawyerOpsB"] = nv
        assert L.deal_seal(g) != base, k


R, C, S = B(1), B(2), P33(3)


def test_one_input_changes_output():
    cases = {
        "zk": (lambda a, b: L.zk_commitment(a, b), [B(1), "n"], [B(2), "m"]),
        "chip": (L.chip_commitment, [B(1), b"d", b"s"], [B(2), b"e", b"t"]),
        "bar": (L.bar_commitment, [B(1), "US-CA", "1"], [B(2), "US-NY", "2"]),
        "slotPolicy": (L.slot_policy, ["A", "r"], ["B", "q"]),
        "bind": (L.bind_msg, [R, C, S, "A"], [B(9), B(8), P33(7), "B"]),
        "sigmsg": (L.contract_sig_msg, [R, "w", "LA"], [B(9), "x", "LB"]),
        "seal": (L.signed_contract_seal, [R, "w", S, B(1, 64), S, B(2, 64)], [B(9), "x", P33(9), B(3, 64), P33(8), B(4, 64)]),
        "pqhash": (lambda a, b, c: L.pq_key_hash([a, b, c]), [B(1), B(2), B(3)], [B(2), B(1), B(4)]),
        "pqbind": (L.pq_bind_msg, [R, S, C], [B(9), P33(9), B(8)]),
        "ops": (L.ops_bind_msg, [R, "o", S, C, "LA"], [B(9), "p", P33(9), B(8), "LB"]),
        "presence": (L.presence_msg, [R, "A", C, S], [B(9), "B", B(8), B(7)]),
        "tuple": (lambda t, a, b: L.tuple_hash(t, [a, b]), ["t", b"a", b"b"], ["u", b"c", b"d"]),
    }
    for name, (fn, x, y) in cases.items():
        base = fn(*x)
        for i in range(len(x)):
            z = list(x)
            z[i] = y[i]
            assert fn(*z) != base, (name, i)


def test_lp_prevents_boundary_shift_and_merkle_inputs():
    assert L.tuple_hash("t", [b"ab", b"c"]) != L.tuple_hash("t", [b"a", b"bc"])
    base = L.contract_root([B(1), B(2)], [b"a", b"b"])
    assert L.contract_root([B(3), B(2)], [b"a", b"b"]) != base
    assert L.contract_root([B(1), B(2)], [b"a", b"c"]) != base
    assert L.contract_root([B(2), B(1)], [b"b", b"a"]) != base


def test_pq_key_hash_order_matters():
    assert L.pq_key_hash([B(1), B(2), B(3)]) != L.pq_key_hash([B(3), B(2), B(1)])


def test_settled_rules():
    with pytest.raises(ValueError):
        L.clause_bytes("a\rb")
    assert L.clause_bytes("\ufeff\ufeffa\r\nb") == "\ufeffa\nb".encode()
    k = [B(1), B(2), B(3)]
    assert L.pq_key_hash(k) == L.tuple_hash("legx/pq-keyset/v1", k)
    assert L.gate_memo(b"env")["MemoData"] == L.sha(b"env").hex().upper()
    assert L.gate_memo(b"env") != L.gate_memo(b"enw")
    assert L.zk_commitment(B(1), "123") != L.zk_commitment(B(1), "124")
