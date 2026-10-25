"""Independent reference of the DESIGN.md section 6 recipes. Written from the DESIGN text only. Stdlib only."""
import hashlib
import struct
import unicodedata

# Source: https://www.rfc-editor.org/rfc/rfc9162.html (SHA-256, RFC 9162 section 2.1)


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def u(s: str) -> bytes:
    return s.encode("utf-8")


# DESIGN 6 intro. Source: https://csrc.nist.gov/pubs/sp/800/185/final (idea only)
def LP(x: bytes) -> bytes:
    return u32(len(x)) + x


def tuple_hash(tag: str, parts: list[bytes]) -> bytes:
    return sha(LP(u(tag)) + b"".join(LP(p) for p in parts))


# DESIGN 6.1. Source: https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.1
def clause_bytes(text: str) -> bytes:
    t = unicodedata.normalize("NFC", text.removeprefix("\ufeff")).replace("\r\n", "\n")
    if "\r" in t:
        raise ValueError("lone CR refused")
    return u(t)


def leaf_data(i: int, salt: bytes, clause: bytes) -> bytes:
    return LP(u("legx/clause/v1")) + u32(i) + LP(salt) + LP(clause)


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return sha(b"")
    if len(leaves) == 1:
        return sha(b"\x00" + leaves[0])
    k = 1 << (len(leaves) - 1).bit_length() - 1  # largest power of two < n
    return sha(b"\x01" + merkle_root(leaves[:k]) + merkle_root(leaves[k:]))


def contract_root(salts: list[bytes], clauses: list[bytes]) -> bytes:
    return merkle_root([leaf_data(i, s, c) for i, (s, c) in enumerate(zip(salts, clauses))])


# DESIGN 6.2
def zk_commitment(zk_salt32: bytes, n_side: str) -> bytes:
    return tuple_hash("legx/zk-identity/v1", [zk_salt32, u(n_side)])


# DESIGN 6.17 IDS_DISTINCT, OD-29: X = utf8(N_side) (zkpassport) or SHA-256(DG1) (nfc-chip)
def distinct_tag(deal_id: str, x: bytes) -> bytes:
    return tuple_hash("legx/id-distinct/v1", [u(deal_id), x])


def chip_commitment(salt32: bytes, dg1: bytes, sod: bytes) -> bytes:
    return tuple_hash("legx/passport-commit/v1", [salt32, LP(dg1) + LP(sod)])


def bar_commitment(salt32: bytes, jurisdiction: str, bar_number: str) -> bytes:
    return tuple_hash("legx/bar-commit/v1", [salt32, u(jurisdiction + ":" + bar_number)])


# DESIGN 6.4 (roles: CLIENT_ROLES for A/B, LAWYER_ROLES for LA/LB)
CLIENT_ROLES = "phone,second-authenticator,recovery-agent"
LAWYER_ROLES = "console,firm-hsm,partner"


def slot_policy(slot: str, roles: str) -> bytes:
    return tuple_hash("legx/slot-policy/v1", [u(slot), u32(2), u32(3), u(roles)])


# DESIGN 6.5 (slot_pub is the 33-byte 0xED||key form, see Design questions)
def bind_msg(root: bytes, c_side: bytes, slot_pub: bytes, side: str) -> bytes:
    return tuple_hash("legx/binding/v1", [root, c_side, slot_pub, u(side)])


# DESIGN 6.6
SEAL_FIELDS = ["contractRoot", "signedContractSeal", "walletAddress", "xPubA", "xPubB", "C_A", "C_B",
               "idMethodA", "idMethodB", "identityPolicy", "lawyerPubA", "lawyerPubB", "LC_A", "LC_B",
               "lawyerOpsA", "lawyerOpsB", "releaserAccount", "slotPolicyA", "slotPolicyLA",
               "slotPolicyB", "slotPolicyLB", "pqKeyHashA", "pqKeyHashLA", "pqKeyHashB", "pqKeyHashLB",
               "signerAccounts", "quorum", "payoutA", "payoutB"]
_TEXT = {"walletAddress", "idMethodA", "idMethodB", "identityPolicy", "lawyerOpsA", "lawyerOpsB",
         "releaserAccount", "payoutA", "payoutB"}




def deal_seal(f: dict) -> bytes:
    if f["releaserAccount"] != f["lawyerOpsB"]:
        raise ValueError("releaserAccount must equal lawyerOpsB")
    parts = []
    for k in SEAL_FIELDS:
        v = f[k]
        if k == "signerAccounts":
            v = u(",".join(sorted(v, key=u)))
        elif k == "quorum":
            v = u32(v)
        elif k in _TEXT:
            v = u(v)
        parts.append(v)
    return tuple_hash("legx/dealseal/v1", parts)


def domain(root: bytes, seal: bytes) -> bytes:
    return b"\x01" + root + seal


# DESIGN 6.7
def condition(preimage: bytes) -> bytes:
    assert len(preimage) == 32
    return bytes.fromhex("A0258020") + sha(preimage) + bytes.fromhex("810120")


def fulfillment(preimage: bytes) -> bytes:
    assert len(preimage) == 32
    return bytes.fromhex("A0228020") + preimage


# DESIGN 6.12
def contract_sig_msg(root: bytes, wallet: str, role: str) -> bytes:
    return tuple_hash("legx/contract-sign/v1", [root, u(wallet), u(role)])


def signed_contract_seal(root, wallet, pub_a, sig_la, pub_b, sig_lb) -> bytes:
    return tuple_hash("legx/signed-contract/v1", [root, u(wallet), pub_a, sig_la, pub_b, sig_lb])


def nft_uri(seal: bytes) -> str:
    return u("legx:sc:v1:" + seal.hex().upper()).hex().upper()


def mint_memo(pub_a, sig_la, pub_b, sig_lb) -> dict:
    data = b"\x01" + pub_a + sig_la + pub_b + sig_lb
    assert len(data) == 195
    return {"MemoType": u("legx/contract-sigs/v1").hex().upper(), "MemoData": data.hex().upper()}


# DESIGN 6.13
def pq_key_hash(pubs: list[bytes]) -> bytes:
    return tuple_hash("legx/pq-keyset/v1", pubs)  # three raw ML-DSA-65 keys, role order


def pq_bind_msg(seal: bytes, slot_pub: bytes, key_hash: bytes) -> bytes:
    return tuple_hash("legx/pq-binding/v1", [seal, slot_pub, key_hash])


# DESIGN 6.14
def ops_bind_msg(root, ops_account: str, lawyer_pub, lc, role: str) -> bytes:
    return tuple_hash("legx/ops-binding/v1", [root, u(ops_account), lawyer_pub, lc, u(role)])


# DESIGN 6.15
def presence_msg(seal: bytes, side: str, ledger_hash: bytes, lawyer_nonce: bytes) -> bytes:
    return tuple_hash("legx/passport-presence/v1", [seal, u(side), ledger_hash, lawyer_nonce])


# DESIGN 6.17
def gate_memo(envelope: bytes) -> dict:  # leaf hash = SHA-256 of the exact DSSE envelope bytes (6 intro)
    return {"MemoType": u("legx/release-gate/v1").hex().upper(), "MemoData": sha(envelope).hex().upper()}


# DESIGN 6.13 EXTERNAL_MU. Source: https://csrc.nist.gov/pubs/fips/204/final (Algorithm 2 line 10, Algorithm 7 line 6)
def mldsa_mu(public_key: bytes, ctx: bytes, msg: bytes) -> bytes:
    assert len(ctx) < 256
    tr = hashlib.shake_256(public_key).digest(64)
    return hashlib.shake_256(tr + bytes([0, len(ctx)]) + ctx + msg).digest(64)
