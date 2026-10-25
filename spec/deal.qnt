// -*- mode: Bluespec; -*-
// The deal wallet as a state machine, with FROST slots, the identity method and the release gate.
// Source: DESIGN.md 5.1 (states, I1 to I8), 6.4 (FROST slots), 6.10 and 6.15 (identity), 6.17 (release gate).
// Language: https://quint.sh/docs/lang  Checking: https://quint.sh/docs/checking-properties
//
// One state variable `d` holds the whole deal, so every action writes it once (Quint has no UNCHANGED).
// Honest actions, faults and attacker actions are separate. Attacker actions call the same acceptance
// logic as the honest ones, with hostile inputs, so they succeed only if a guard is missing.
module deal {
  // ---------- Types ----------

  // DESIGN 5.1. Names match packages/core/src/machine.ts, so traces replay one to one.
  type St = DRAFT | CONTRACT_SIGNED | SHELL_OPEN | QUARANTINED | KEYS_READY | WALLET_LOCKED
          | VERIFIED | SHIPPED | RECEIVED | FUNDED | PAID_OUT | REFUNDED | DISPUTED | EXPIRED | CLOSED

  // DESIGN 6.10: "zkpassport" (method A) or "nfc-chip" (method B). The seal's identityPolicy allows one or both.
  type IdMethod = Zk | Chip
  type Policy = PolicyZk | PolicyZkOrChip | PolicyChip

  // DESIGN 6.4, recovery rules.
  type Recovery = RecNone | RecPending | RecCancelled | RecDone

  // A 4-of-4 transaction from the deal wallet, waiting for slot signatures.
  type Prop = NoProp | PayBob | RefundAlice | CloseAccount | Rotate(str)

  // Who sends the EscrowFinish (DESIGN D4).
  type Who = Nobody | Releaser | Stranger

  // A passport attestation at release (DESIGN 6.15).
  type Att = { present: bool, valid: bool, method: IdMethod }

  // One FROST 2-of-3 slot (DESIGN 6.4). Holders: 1 phone or console, 2 security key or HSM,
  // 3 recovery agent or partner. `epoch` counts rotations on the ledger; the signer list holds the
  // current epoch's group key.
  type Slot = {
    held: Set[int],
    epoch: int,
    rec: Recovery,
    recHours: int,
    recCancelled: bool,
    unsafe: bool,
    compromisedEpoch: int,
  }

  type Ledger = {
    exists: bool,
    masterOn: bool,
    regularKey: bool,
    delegate: bool,
    quorum: int,
    depositAuth: bool,
    preauthReleaserOnly: bool,
    escrowOpen: bool,
    funds: bool,
  }

  // Audit records, written when something happens, so invariants can look back at it.
  type Finish = { done: bool, by: Who, gateOk: bool, locked: bool, attA: Att, attB: Att }
  type SlotSig = { slot: str, shares: int, held: int }
  type Rotation = { slot: str, sigs: int, newSeal: bool, newNft: bool }
  type Audit = {
    lastOutSigs: int,
    lastOutStale: bool,
    exits: int,
    lastSign: SlotSig,
    lastRotation: Rotation,
    wasClosed: bool,
  }

  // The machine.ts event for this step, for the conformance replay. Model-only steps use "NONE".
  type Event = { t: str, sigs: int, gatePassed: bool, to: str }

  type Deal = {
    st: St,
    ledger: Ledger,
    slots: str -> Slot,
    policy: Policy,
    onboard: str -> IdMethod,
    att: str -> Att,
    gate: str -> bool,
    deadlinePassed: bool,
    codeLeaked: bool,
    wasLocked: bool,
    faults: int,
    prop: Prop,
    sigs: Set[(str, int)],
    fin: Finish,
    audit: Audit,
    ev: Event,
  }

  // ---------- Constants ----------

  pure val SLOTS = Set("A", "LA", "B", "LB")
  pure val CLIENTS = Set("A", "B")
  pure val LAWYERS = Set("LA", "LB")
  pure val HOLDERS = Set(1, 2, 3)
  pure val OUTSIDER = 9           // a participant outside the slot policy
  pure val THRESHOLD = 2          // FROST 2-of-3
  pure val QUORUM = 4             // client A, lawyer A, client B, lawyer B
  pure val DELAY = 72             // recovery delay in hours
  pure val TICK = 24              // the clock moves in steps of this many hours
  pure val MAX_FAULTS = 3         // bounds the environment, so TLC sees a finite state space
  pure val LIVE_FAULTS = 1        // faults per behaviour in the liveness check (2 gives over 7 million states)
  pure val MAX_EPOCH = 1          // at most one rotation per slot, for the same reason
  pure val METHODS = Set(Zk, Chip)
  pure val POLICIES = Set(PolicyZk, PolicyZkOrChip, PolicyChip)

  // DESIGN 6.17: one boolean per check. Derived checks are computed from the model state;
  // the others are evidence the model does not track, so the environment decides them.
  pure val DERIVED_CHECKS = Set("LOCK_OK", "RELEASER_SEALED", "PASSPORT_A_OK", "PASSPORT_B_OK", "IDENTITY_POLICY_OK")
  pure val ENV_CHECKS = Set(
    "CONTRACT_SEAL_OK", "BAR_A_OK", "BAR_B_OK", "ATTORNEY_CREDENTIAL_A_OK", "ATTORNEY_CREDENTIAL_B_OK",
    "OPS_BINDINGS_OK", "ONBOARDING_OK", "IDS_DISTINCT", "PQ_BINDINGS_OK", "SLOT_SETUP_OK",
  )
  pure val CHECKS = DERIVED_CHECKS.union(ENV_CHECKS)

  pure val NO_ATT: Att = { present: false, valid: false, method: Zk }
  pure val NEW_SLOT: Slot = {
    held: Set(), epoch: 0, rec: RecNone, recHours: 0, recCancelled: false, unsafe: false, compromisedEpoch: -1,
  }
  pure val NO_EVENT: Event = { t: "NONE", sigs: 0, gatePassed: false, to: "" }

  // ---------- Pure rules ----------

  // DESIGN 6.10: which methods the sealed identityPolicy allows.
  pure def allowed(p: Policy, m: IdMethod): bool = match p {
    | PolicyZk => m == Zk
    | PolicyZkOrChip => true
    | PolicyChip => m == Chip
  }

  // DESIGN 6.15 and 6.17 (PASSPORT_X_OK, IDENTITY_POLICY_OK): a present, valid attestation of an
  // allowed method, the same method as onboarding.
  pure def attOk(p: Policy, onboarded: IdMethod, a: Att): bool = and {
    a.present,
    a.valid,
    allowed(p, a.method),
    a.method == onboarded,
  }

  // DESIGN 6.9: the lock checker, reduced to the fields the model tracks.
  pure def lockCheck(l: Ledger): bool = and {
    not(l.masterOn),
    not(l.regularKey),
    not(l.delegate),
    l.quorum == QUORUM,
    l.depositAuth,
    l.preauthReleaserOnly,
    l.escrowOpen,
  }

  pure def gatePasses(g: str -> bool): bool = CHECKS.forall(c => g.get(c))

  pure def isFundedLike(s: St): bool = s.in(Set(FUNDED, DISPUTED))
  pure def hasEscrow(s: St): bool = s.in(Set(QUARANTINED, KEYS_READY, WALLET_LOCKED, VERIFIED, SHIPPED, RECEIVED))
  pure def hasSlots(s: St): bool = not(s.in(Set(DRAFT, CONTRACT_SIGNED, SHELL_OPEN, QUARANTINED, CLOSED)))

  // XRPL multisign (DESIGN 6.8, 7.5): every signature must be by a key in the current signer list,
  // and the count must reach the quorum. A key of an old epoch is not in the list any more.
  // Source: https://xrpl.org/docs/concepts/accounts/multi-signing
  pure def multisigOk(l: Ledger, slots: str -> Slot, sigs: Set[(str, int)]): bool = and {
    l.quorum > 0,
    sigs.forall(x => x._2 == slots.get(x._1).epoch),
    sigs.size() >= l.quorum,
  }

  // Who may sign a transaction from the deal wallet (master key, regular key or signer list).
  // Source: https://xrpl.org/docs/concepts/accounts/cryptographic-keys
  pure def ledgerAccepts(l: Ledger, slots: str -> Slot, sigs: Set[(str, int)], byMaster: bool, byRegularKey: bool): bool =
    if (byMaster) l.masterOn
    else if (byRegularKey) l.regularKey
    else multisigOk(l, slots, sigs)

  // DESIGN D4: with DepositAuth on, the ledger checks the account that sends the EscrowFinish.
  // Source: https://xrpl.org/docs/concepts/accounts/depositauth
  pure def finishAccepted(l: Ledger, who: Who): bool =
    not(l.depositAuth) or (who == Releaser and l.preauthReleaserOnly)

  // ---------- State ----------

  var d: Deal

  // A new deal, with the identityPolicy the parties chose.
  pure def draft(policy: Policy): Deal = {
    st: DRAFT,
    ledger: {
      exists: false, masterOn: false, regularKey: false, delegate: false, quorum: 0,
      depositAuth: false, preauthReleaserOnly: false, escrowOpen: false, funds: false,
    },
    slots: SLOTS.mapBy(_ => NEW_SLOT),
    policy: policy,
    onboard: CLIENTS.mapBy(_ => Zk),
    att: CLIENTS.mapBy(_ => NO_ATT),
    gate: CHECKS.mapBy(_ => false),
    deadlinePassed: false,
    codeLeaked: false,
    wasLocked: false,
    faults: 0,
    prop: NoProp,
    sigs: Set(),
    fin: { done: false, by: Nobody, gateOk: false, locked: false, attA: NO_ATT, attB: NO_ATT },
    audit: {
      lastOutSigs: 0, lastOutStale: false, exits: 0,
      lastSign: { slot: "", shares: 0, held: 0 },
      lastRotation: { slot: "", sigs: 0, newSeal: false, newNft: false },
      wasClosed: false,
    },
    ev: { t: "INIT", sigs: 0, gatePassed: false, to: "" },
  }

  // The state the happy path reaches right after the release (checked by happyPathTest below).
  pure def funded(policy: Policy, mA: IdMethod, mB: IdMethod): Deal = {
    val attA = { present: true, valid: true, method: mA }
    val attB = { present: true, valid: true, method: mB }
    { ...draft(policy),
      st: FUNDED,
      ledger: {
        exists: true, masterOn: false, regularKey: false, delegate: false, quorum: QUORUM,
        depositAuth: true, preauthReleaserOnly: true, escrowOpen: false, funds: true,
      },
      slots: SLOTS.mapBy(_ => { ...NEW_SLOT, held: HOLDERS }),
      onboard: Map("A" -> mA, "B" -> mB),
      att: Map("A" -> attA, "B" -> attB),
      gate: CHECKS.mapBy(_ => true),
      wasLocked: true,
      fin: { done: true, by: Releaser, gateOk: true, locked: true, attA: attA, attB: attB },
      ev: { t: "RELEASE_ESCROW", sigs: 1, gatePassed: true, to: "" },
    }
  }

  action initWith(policy: Policy): bool = d' = draft(policy)

  action initFundedWith(policy: Policy, mA: IdMethod, mB: IdMethod): bool = d' = funded(policy, mA, mB)

  action init = {
    nondet policy = POLICIES.oneOf()
    initWith(policy)
  }

  // Starts in FUNDED, so short runs reach recovery, rotation and the exits. Used by the mutation
  // tests; happyPathTest shows `init` reaches this state.
  action initFunded = {
    nondet policy = POLICIES.oneOf()
    nondet mA = METHODS.filter(m => allowed(policy, m)).oneOf()
    nondet mB = METHODS.filter(m => allowed(policy, m)).oneOf()
    initFundedWith(policy, mA, mB)
  }

  // Every transition goes through here: it records whether the deal was CLOSED before the step (I6).
  action go(n: Deal): bool =
    d' = { ...n, audit: { ...n.audit, wasClosed: d.audit.wasClosed or d.st == CLOSED } }

  pure def ev(t: str): Event = { ...NO_EVENT, t: t }

  // ---------- Honest setup (DESIGN 5.2) ----------

  action signContract = all {
    d.st == DRAFT,
    go({ ...d, st: CONTRACT_SIGNED, ev: ev("SIGN_CONTRACT") }),
  }

  // The shell is funded with the reserve; its master key is the setup key.
  action openShell = all {
    d.st == CONTRACT_SIGNED,
    go({ ...d, st: SHELL_OPEN, ledger: { ...d.ledger, exists: true, masterOn: true }, ev: ev("OPEN_SHELL") }),
  }

  // Before the escrow, the deal can be abandoned. A shell is deleted with its master key.
  action abandon = all {
    d.st.in(Set(CONTRACT_SIGNED, SHELL_OPEN)),
    not(d.ledger.exists) or d.ledger.masterOn,
    go({ ...d, st: CLOSED, ledger: { ...d.ledger, exists: false }, ev: ev("ABANDON") }),
  }

  // Alice's EscrowCreate with the sealed condition and CancelAfter.
  action fundQuarantine = all {
    d.st == SHELL_OPEN,
    go({ ...d, st: QUARANTINED, ledger: { ...d.ledger, escrowOpen: true }, ev: ev("FUND_QUARANTINE") }),
  }

  // DESIGN 6.4: a repair gives a new device a share, after a recovery. Two holders help.
  action shareJoins(s: str, h: int): bool = {
    val sl = d.slots.get(s)
    val held2 = sl.held.union(Set(h))
    val repaired = held2 == HOLDERS
    all {
      hasSlots(d.st),
      sl.rec == RecDone,
      not(sl.held.contains(h)),
      sl.held.size() >= THRESHOLD,
      go({ ...d,
        slots: d.slots.set(s, {
          ...sl,
          held: held2,
          rec: if (repaired) RecNone else sl.rec,
          recHours: if (repaired) 0 else sl.recHours,
          recCancelled: if (repaired) false else sl.recCancelled,
        }),
        ev: NO_EVENT,
      }),
    }
  }

  // The DKG gives every slot its three holders, and each slot test-signs with all three pairs
  // (DESIGN 6.4 rule 4). Both clients are onboarded with a method the policy allows (DESIGN 6.10).
  action keysMade(mA: IdMethod, mB: IdMethod): bool = all {
    d.st == QUARANTINED,
    allowed(d.policy, mA),
    allowed(d.policy, mB),
    go({ ...d,
      st: KEYS_READY,
      slots: SLOTS.mapBy(_ => { ...NEW_SLOT, held: HOLDERS }),
      onboard: Map("A" -> mA, "B" -> mB),
      ev: ev("KEYS_MADE"),
    }),
  }

  // DESIGN 5.2 P4: signer list, DepositAuth with one preauth, master off. The honest parties do not
  // remove a regular key or a delegate they do not know about; the lock checker must find them.
  action lockWallet = all {
    d.st == KEYS_READY,
    d.ledger.masterOn,
    go({ ...d,
      st: WALLET_LOCKED,
      ledger: { ...d.ledger, quorum: QUORUM, masterOn: false, depositAuth: true, preauthReleaserOnly: true },
      wasLocked: true,
      ev: ev("LOCK_WALLET"),
    }),
  }

  // DESIGN 6.9: the lock checker passes on a validated ledger.
  action verifyOk = all {
    d.st == WALLET_LOCKED,
    lockCheck(d.ledger),
    go({ ...d, st: VERIFIED, ev: ev("VERIFY_OK") }),
  }

  // OD-37: Bob's slot-B shipment, then Alice's slot-A receipt (condition ok). Release is legal only from RECEIVED (OD-38).
  action ship = all {
    d.st == VERIFIED,
    go({ ...d, st: SHIPPED, ev: ev("SHIP_SIGNED") }),
  }

  action receive = all {
    d.st == SHIPPED,
    go({ ...d, st: RECEIVED, ev: ev("RECEIPT_SIGNED") }),
  }

  // ---------- Identity and the release gate (DESIGN 6.10, 6.15, 6.17) ----------

  // A client does the release-time passport check. A new attestation makes the old gate result stale.
  action attest(side: str, m: IdMethod, valid: bool): bool = {
    val a = { present: true, valid: valid, method: m }
    val good = attOk(d.policy, d.onboard.get(side), a)
    all {
      d.st == RECEIVED,
      not(attOk(d.policy, d.onboard.get(side), d.att.get(side))),
      good or d.faults < MAX_FAULTS,
      go({ ...d,
        att: d.att.set(side, a),
        gate: CHECKS.mapBy(_ => false),
        faults: if (good) d.faults else d.faults + 1,
        ev: NO_EVENT,
      }),
    }
  }

  // An attestation becomes older than its freshness window (DESIGN 5.4).
  action attestExpire(side: str): bool = all {
    d.st == RECEIVED,
    d.att.get(side).valid,
    d.faults < MAX_FAULTS,
    go({ ...d,
      att: d.att.set(side, { ...d.att.get(side), valid: false }),
      gate: CHECKS.mapBy(_ => false),
      faults: d.faults + 1,
      ev: NO_EVENT,
    }),
  }

  pure def passportOk(x: Deal, side: str): bool = attOk(x.policy, x.onboard.get(side), x.att.get(side))

  // One check from the model state (DESIGN 6.17).
  pure def derivedCheck(x: Deal, c: str): bool =
    if (c == "LOCK_OK") lockCheck(x.ledger)
    else if (c == "RELEASER_SEALED") x.ledger.preauthReleaserOnly
    else if (c == "PASSPORT_A_OK") passportOk(x, "A")
    else if (c == "PASSPORT_B_OK") passportOk(x, "B")
    else CLIENTS.forall(s => allowed(x.policy, x.att.get(s).method) and x.att.get(s).method == x.onboard.get(s))

  // checkRelease on one validated ledger. `bad` is an evidence check that fails ("" for none).
  // A gate with several failing checks blocks just like a gate with one, so one is enough.
  action evalGate(bad: str): bool = all {
    d.st == RECEIVED,
    bad == "" or d.faults < MAX_FAULTS,
    go({ ...d,
      gate: CHECKS.mapBy(c => if (DERIVED_CHECKS.contains(c)) derivedCheck(d, c) else c != bad),
      faults: if (bad == "") d.faults else d.faults + 1,
      ev: NO_EVENT,
    }),
  }

  // The EscrowFinish. Only funds the wallet if the ledger accepts the sender.
  action finish(who: Who): bool = all {
    hasEscrow(d.st),
    d.ledger.escrowOpen,
    not(d.deadlinePassed),
    finishAccepted(d.ledger, who),
    go({ ...d,
      st: FUNDED,
      ledger: { ...d.ledger, escrowOpen: false, funds: true },
      fin: {
        done: true, by: who, gateOk: gatePasses(d.gate), locked: lockCheck(d.ledger),
        attA: d.att.get("A"), attB: d.att.get("B"),
      },
      ev: { t: "RELEASE_ESCROW", sigs: 1, gatePassed: gatePasses(d.gate), to: "" },
    }),
  }

  // Lawyer B's console releases only from RECEIVED, and only when every gate check passes (I8).
  action release = all {
    d.st == RECEIVED,
    gatePasses(d.gate),
    finish(Releaser),
  }

  // ---------- Deadline and exits ----------

  action cancelAfterPasses = all {
    hasEscrow(d.st),
    not(d.deadlinePassed),
    go({ ...d, deadlinePassed: true, ev: NO_EVENT }),
  }

  action escrowCancel = all {
    hasEscrow(d.st),
    d.deadlinePassed,
    d.ledger.escrowOpen,
    go({ ...d, st: EXPIRED, ledger: { ...d.ledger, escrowOpen: false }, ev: ev("CANCEL_AFTER_PASSED") }),
  }

  action openDispute = all {
    d.st == FUNDED,
    go({ ...d, st: DISPUTED, ev: ev("OPEN_DISPUTE") }),
  }

  pure def allowedProps(x: Deal): Set[Prop] =
    if (isFundedLike(x.st))
      Set(PayBob, RefundAlice).union(
        SLOTS.filter(s => x.slots.get(s).unsafe and x.slots.get(s).epoch < MAX_EPOCH).map(s => Rotate(s)))
    else if (x.st.in(Set(PAID_OUT, REFUNDED, EXPIRED)) and x.wasLocked) Set(CloseAccount)
    else Set()

  // The parties agree on one 4-of-4 transaction and start collecting signatures.
  action propose(p: Prop): bool = all {
    d.prop == NoProp,
    allowedProps(d).contains(p),
    go({ ...d, prop: p, sigs: Set(), ev: NO_EVENT }),
  }

  // One slot produces a FROST signature (DESIGN 6.4) with the shares of `signers`. verifyShare drops
  // any share that is not from a current holder. Any pair with holder 3 is the recovery path.
  action slotSignWith(s: str, signers: Set[int]): bool = {
    val sl = d.slots.get(s)
    val valid = signers.intersect(sl.held)
    val viaRecovery = valid.contains(3)
    all {
      d.prop != NoProp,
      hasSlots(d.st),
      not(d.sigs.contains((s, sl.epoch))),
      valid.size() >= THRESHOLD,
      not(viaRecovery) or sl.rec == RecPending,
      not(viaRecovery) or sl.recHours >= DELAY,
      go({ ...d,
        slots: if (viaRecovery) d.slots.set(s, { ...sl, rec: RecDone }) else d.slots,
        sigs: d.sigs.union(Set((s, sl.epoch))),
        audit: { ...d.audit, lastSign: { slot: s, shares: valid.size(), held: sl.held.size() } },
        ev: NO_EVENT,
      }),
    }
  }

  // Normal signing: shares 1 + 2.
  action slotSign(s: str): bool = slotSignWith(s, Set(1, 2))

  // Recovery signing: 2 + 3 or 1 + 3, after the delay.
  action recoverySign(s: str): bool = {
    nondet pair = Set(Set(2, 3), Set(1, 3)).oneOf()
    slotSignWith(s, pair)
  }

  pure def isPayout(p: Prop): bool = p == PayBob or p == RefundAlice

  // Submit a transaction from the deal wallet. The ledger decides; the deal moves only if it accepts.
  action submitOut(p: Prop, sigs: Set[(str, int)], byMaster: bool, byRegularKey: bool): bool = {
    val outSigs = if (byMaster or byRegularKey) 1 else sigs.size()
    val stale = sigs.exists(x => x._2 != d.slots.get(x._1).epoch)
    val award = d.st == DISPUTED
    val n = { ...d,
      prop: if (p == d.prop) NoProp else d.prop,
      sigs: if (p == d.prop) Set() else d.sigs,
      audit: { ...d.audit, lastOutSigs: if (d.wasLocked) outSigs else d.audit.lastOutSigs, lastOutStale: stale },
    }
    all {
      d.ledger.exists,
      ledgerAccepts(d.ledger, d.slots, sigs, byMaster, byRegularKey),
      match p {
        | PayBob => all {
          isFundedLike(d.st),
          d.ledger.funds,
          go({ ...n,
            st: PAID_OUT,
            ledger: { ...d.ledger, funds: false },
            audit: { ...n.audit, exits: d.audit.exits + 1 },
            ev: { t: if (award) "AWARD" else "PAY_BOB", sigs: outSigs, gatePassed: false, to: if (award) "BOB" else "" },
          }),
        }
        | RefundAlice => all {
          isFundedLike(d.st),
          d.ledger.funds,
          go({ ...n,
            st: REFUNDED,
            ledger: { ...d.ledger, funds: false },
            audit: { ...n.audit, exits: d.audit.exits + 1 },
            ev: { t: if (award) "AWARD" else "REFUND_ALICE", sigs: outSigs, gatePassed: false, to: if (award) "ALICE" else "" },
          }),
        }
        | CloseAccount => all {
          d.st.in(Set(PAID_OUT, REFUNDED, EXPIRED)),
          go({ ...n,
            st: CLOSED,
            ledger: { ...d.ledger, exists: false },
            ev: { t: "CLOSE", sigs: outSigs, gatePassed: false, to: "" },
          }),
        }
        // DESIGN 6.4: a new DKG, a 4-of-4 SignerListSet, a new seal, and for a lawyer slot a new
        // contract signature and NFT. Modelled as one step, since only the signer list moves keys.
        | Rotate(s) => all {
          isFundedLike(d.st),
          d.slots.get(s).epoch < MAX_EPOCH,
          go({ ...n,
            slots: d.slots.set(s, { ...NEW_SLOT, held: HOLDERS, epoch: d.slots.get(s).epoch + 1, compromisedEpoch: d.slots.get(s).compromisedEpoch }),
            audit: { ...n.audit, lastRotation: { slot: s, sigs: outSigs, newSeal: true, newNft: LAWYERS.contains(s) } },
            ev: NO_EVENT,
          }),
        }
        | NoProp => all { false, go(n) }
      },
    }
  }

  action submit = submitOut(d.prop, d.sigs, false, false)

  // An expired shell that was never locked is closed with its master key.
  action closeByMaster = all {
    d.st == EXPIRED,
    not(d.wasLocked),
    submitOut(CloseAccount, Set(), true, false),
  }

  // ---------- Slot recovery and rotation (DESIGN 6.4) ----------

  // A client recovery needs a fresh proof with the same identifier and a face match; a lawyer
  // recovery needs a request signed by the firm's operations account.
  action recoveryStartWith(s: str, sameId: bool, faceMatch: bool, opsRequest: bool): bool = {
    val sl = d.slots.get(s)
    all {
      hasSlots(d.st),
      not(sl.held.contains(1)) or not(sl.held.contains(2)),
      sl.rec.in(Set(RecNone, RecCancelled)),
      if (CLIENTS.contains(s)) sameId and faceMatch else opsRequest,
      go({ ...d, slots: d.slots.set(s, { ...sl, rec: RecPending, recHours: 0, recCancelled: false }), ev: NO_EVENT }),
    }
  }

  action recoveryStart(s: str): bool = recoveryStartWith(s, true, true, true)

  // The clock moves; every pending recovery gets older.
  action tick = all {
    SLOTS.exists(s => d.slots.get(s).rec == RecPending and d.slots.get(s).recHours < DELAY),
    go({ ...d,
      slots: SLOTS.mapBy(s => {
        val sl = d.slots.get(s)
        if (sl.rec == RecPending) { ...sl, recHours: if (sl.recHours + TICK > DELAY) DELAY else sl.recHours + TICK }
        else sl
      }),
      ev: NO_EVENT,
    }),
  }

  // A refresh changes the shares but keeps the group key: hygiene, not revocation. It does not
  // clear `unsafe`.
  action refresh(s: str): bool = {
    val sl = d.slots.get(s)
    all {
      hasSlots(d.st),
      sl.held == HOLDERS,
      go({ ...d, slots: d.slots.set(s, { ...sl, unsafe: sl.unsafe }), ev: NO_EVENT }),
    }
  }

  // ---------- Faults (bounded by MAX_FAULTS) ----------

  action shareLost(s: str, h: int): bool = {
    val sl = d.slots.get(s)
    all {
      hasSlots(d.st),
      sl.held.contains(h),
      d.faults < MAX_FAULTS,
      go({ ...d, slots: d.slots.set(s, { ...sl, held: sl.held.exclude(Set(h)) }), faults: d.faults + 1, ev: NO_EVENT }),
    }
  }

  // The old device cancels a recovery during the delay.
  action recoveryCancel(s: str): bool = {
    val sl = d.slots.get(s)
    all {
      sl.rec == RecPending,
      d.faults < MAX_FAULTS,
      go({ ...d, slots: d.slots.set(s, { ...sl, rec: RecCancelled, recCancelled: true }), faults: d.faults + 1, ev: NO_EVENT }),
    }
  }

  // A share is known to be stolen. Only a rotation on the ledger makes the slot safe again.
  action compromiseShare(s: str): bool = {
    val sl = d.slots.get(s)
    all {
      hasSlots(d.st),
      sl.compromisedEpoch != sl.epoch,
      d.faults < MAX_FAULTS,
      go({ ...d, slots: d.slots.set(s, { ...sl, unsafe: true, compromisedEpoch: sl.epoch }), faults: d.faults + 1, ev: NO_EVENT }),
    }
  }

  // ---------- Attacker actions ----------

  // Alice's side uses the setup key to plant a regular key or a delegate before the lock.
  action plantRegularKey = all {
    d.ledger.exists,
    d.ledger.masterOn,
    not(d.ledger.regularKey),
    go({ ...d, ledger: { ...d.ledger, regularKey: true }, ev: NO_EVENT }),
  }

  action plantDelegate = all {
    d.ledger.exists,
    d.ledger.masterOn,
    not(d.ledger.delegate),
    go({ ...d, ledger: { ...d.ledger, delegate: true }, ev: NO_EVENT }),
  }

  // A stranger learns the release code after the lock (T-A-07). Before the lock only lawyer B knows it.
  action leakCode = all {
    d.wasLocked,
    not(d.codeLeaked),
    go({ ...d, codeLeaked: true, ev: NO_EVENT }),
  }

  // A stranger who knows the code sends the EscrowFinish.
  action strangerFinish = all {
    d.codeLeaked,
    finish(Stranger),
  }

  // A payout signed by one slot, by the master key, or by a planted regular key.
  action singleSignedExit = {
    nondet p = Set(PayBob, RefundAlice).oneOf()
    nondet s = SLOTS.oneOf()
    nondet how = Set("slot", "master", "regularKey").oneOf()
    submitOut(p, if (how == "slot") Set((s, d.slots.get(s).epoch)) else Set(), how == "master", how == "regularKey")
  }

  // DESIGN 5.4: both exit candidates are signed by all four at the same ticket. Someone submits the
  // other candidate after one exit validated; only the first may count.
  action replayCandidate = {
    nondet p = Set(PayBob, RefundAlice).oneOf()
    submitOut(p, SLOTS.map(s => (s, d.slots.get(s).epoch)), false, false)
  }

  // Lawyer B's console is asked to release without both passport checks.
  action skipPassport = all {
    not(passportOk(d, "A") and passportOk(d, "B")),
    release,
  }

  // The recovery agent's share alone, and a share from someone outside the slot policy.
  action soloAgentSign(s: str): bool = slotSignWith(s, Set(3))

  action outsidePolicyShare(s: str): bool = {
    nondet h = HOLDERS.oneOf()
    slotSignWith(s, Set(h, OUTSIDER))
  }

  action earlyRecoverySign(s: str): bool = all {
    d.slots.get(s).recHours < DELAY,
    slotSignWith(s, Set(2, 3)),
  }

  action signAfterCancel(s: str): bool = all {
    d.slots.get(s).rec == RecCancelled,
    slotSignWith(s, Set(2, 3)),
  }

  // Recovery started without the identity proof or the operations-account request.
  action forgedRecoveryStart(s: str): bool = recoveryStartWith(s, false, false, false)

  // Someone with two shares of a rotated-away epoch adds a signature by the old slot key.
  action staleEpochSign(s: str): bool = {
    val sl = d.slots.get(s)
    all {
      d.prop != NoProp,
      sl.epoch > 0,
      go({ ...d, sigs: d.sigs.union(Set((s, sl.epoch - 1))), ev: NO_EVENT }),
    }
  }

  // A rotation submitted with the signatures of only three slots.
  action rotateWithoutOneSlot(s: str): bool = {
    nondet missing = SLOTS.oneOf()
    submitOut(Rotate(s), SLOTS.exclude(Set(missing)).map(x => (x, d.slots.get(x).epoch)), false, false)
  }

  // ---------- Steps ----------

  // CLOSED is terminal. This stutter step keeps Apalache from reporting a closed deal as a deadlock.
  action closedStays = all {
    d.st == CLOSED,
    go({ ...d, ev: NO_EVENT }),
  }

  // Each branch picks only the values it needs, so TLC does not multiply every branch by every choice.
  action stepHonest = any {
    signContract, openShell, abandon, fundQuarantine,
    { nondet mA = METHODS.oneOf()
      nondet mB = METHODS.oneOf()
      keysMade(mA, mB) },
    lockWallet, verifyOk, ship, receive,
    { nondet side = CLIENTS.oneOf()
      attest(side, d.onboard.get(side), true) },
    evalGate(""), release, escrowCancel, openDispute,
    { nondet p = allowedProps(d).union(Set(NoProp)).oneOf()
      propose(p) },
    { nondet s = SLOTS.oneOf()
      slotSign(s) },
    { nondet s = SLOTS.oneOf()
      recoverySign(s) },
    { nondet s = SLOTS.oneOf()
      nondet h = HOLDERS.oneOf()
      shareJoins(s, h) },
    { nondet s = SLOTS.oneOf()
      recoveryStart(s) },
    submit, closeByMaster, tick, closedStays,
  }

  // The deadline passing, and a refresh (which changes nothing the ledger or the seal sees).
  action stepEnv = any {
    cancelAfterPasses,
    { nondet s = SLOTS.oneOf()
      refresh(s) },
  }

  // Faults the deal must survive: a lost share (at most one per slot here), a failed or stale
  // passport check, a failing gate check, a cancelled recovery, a stolen share.
  action stepFault = any {
    { nondet s = SLOTS.oneOf()
      nondet h = HOLDERS.oneOf()
      all { d.slots.get(s).held == HOLDERS, shareLost(s, h) } },
    { nondet side = CLIENTS.oneOf()
      nondet m = METHODS.oneOf()
      nondet valid = Set(true, false).oneOf()
      attest(side, m, valid) },
    { nondet side = CLIENTS.oneOf()
      attestExpire(side) },
    { nondet bad = ENV_CHECKS.oneOf()
      evalGate(bad) },
    { nondet s = SLOTS.oneOf()
      recoveryCancel(s) },
    { nondet s = SLOTS.oneOf()
      compromiseShare(s) },
  }

  // A second lost share: the slot cannot sign any more (DESIGN 6.4, DQ-6). Safety only.
  action stepSecondLoss = {
    nondet s = SLOTS.oneOf()
    nondet h = HOLDERS.oneOf()
    shareLost(s, h)
  }

  action stepAttack = any {
    plantRegularKey, plantDelegate, leakCode, strangerFinish, singleSignedExit, skipPassport, replayCandidate,
    { nondet s = SLOTS.oneOf()
      any { soloAgentSign(s), outsidePolicyShare(s), earlyRecoverySign(s), signAfterCancel(s) } },
    { nondet s = SLOTS.oneOf()
      any { forgedRecoveryStart(s), staleEpochSign(s), rotateWithoutOneSlot(s) } },
  }

  // Every behaviour: honest steps, the environment, faults and attacks. Apalache checks this one.
  action step = any { stepHonest, stepEnv, stepFault, stepSecondLoss, stepAttack }

  // The same branches, weighted for `quint run`. The simulator picks uniformly among the enabled
  // branches, so stepHonest is listed eight times to let random runs reach the deep states
  // (release, close, rotation) within 30 steps. It adds no behaviour that `step` lacks.
  action stepSim = any {
    stepHonest, stepHonest, stepHonest, stepHonest, stepHonest, stepHonest, stepHonest, stepHonest,
    stepEnv, stepFault, stepSecondLoss, stepAttack,
  }

  // For liveness: honest steps, the environment, at most LIVE_FAULTS faults, and the attacker moves
  // that only set a flag. A second lost share and a polluted signature set can block a deal
  // forever, by design (DQ-6), so they are left out here; stepLiveDQ6 shows the first one.
  action stepLive = any {
    stepHonest, stepEnv, all { d.faults < LIVE_FAULTS, stepFault },
    plantRegularKey, plantDelegate, leakCode, strangerFinish,
  }

  // Liveness with two shares of one slot lost: TLC must find a deal that never closes.
  action stepLiveDQ6 = any { stepLive, stepSecondLoss }

  // ---------- Invariants ----------

  pure def lockedNow(l: Ledger): bool =
    not(l.masterOn) and l.quorum == QUORUM and not(l.regularKey) and not(l.delegate)

  // I1 and I3: funds enter only a locked wallet, and it stays locked.
  val invLockedBeforeFunds = d.fin.done implies (d.fin.locked and lockedNow(d.ledger))

  // I2: every outflow after the lock carries all four signatures.
  val invFourSigs = d.audit.lastOutSigs > 0 implies d.audit.lastOutSigs >= QUORUM

  // I8: funds enter only through lawyer B's release, after every gate check passed.
  val invGateBeforeFunds = d.fin.done implies (d.fin.by == Releaser and d.fin.gateOk)

  // I5: at most one exit.
  val invOneExit = d.audit.exits <= 1

  // I6: CLOSED is final.
  val invClosedFinal = d.audit.wasClosed implies d.st == CLOSED

  // No release without two valid attestations, each of a method the policy allows.
  // Written without attOk, so a mutation of the gate's own check cannot weaken it.
  pure def attestationAllowed(p: Policy, a: Att): bool = a.present and a.valid and allowed(p, a.method)

  val invTwoPassports = d.fin.done implies (attestationAllowed(d.policy, d.fin.attA) and attestationAllowed(d.policy, d.fin.attB))

  // A slot with fewer than 2 shares never signs.
  val invTwoShares = d.audit.lastSign.slot != "" implies (d.audit.lastSign.shares >= THRESHOLD and d.audit.lastSign.held >= THRESHOLD)

  // A recovery signature comes at least 72 hours after the start, and never after a cancel.
  val invRecoveryDelay = SLOTS.forall(s => {
    val sl = d.slots.get(s)
    sl.rec == RecDone implies (sl.recHours >= DELAY and not(sl.recCancelled))
  })

  // A rotation is signed by all four slots, with a new seal, and a new NFT for a lawyer slot.
  val invRotateNeedsAll = d.audit.lastRotation.slot != "" implies and {
    d.audit.lastRotation.sigs == QUORUM,
    d.audit.lastRotation.newSeal,
    LAWYERS.contains(d.audit.lastRotation.slot) implies d.audit.lastRotation.newNft,
  }

  // After a rotation, a key of the old epoch never signs an accepted transaction.
  val invOldKeyDead = not(d.audit.lastOutStale)

  // A refresh is not revocation: a slot whose current key had a share stolen stays unsafe.
  val invUnsafeUntilRotated = SLOTS.forall(s => {
    val sl = d.slots.get(s)
    sl.compromisedEpoch == sl.epoch implies sl.unsafe
  })

  val invAll = and {
    invLockedBeforeFunds, invFourSigs, invGateBeforeFunds, invOneExit, invClosedFinal,
    invTwoPassports, invTwoShares, invRecoveryDelay, invRotateNeedsAll, invOldKeyDead, invUnsafeUntilRotated,
  }

  // ---------- Witnesses (the run must reach these, or the invariants are vacuous) ----------

  val witReleased = d.fin.done
  val witClosedAfterExit = d.st == CLOSED and d.audit.exits == 1
  val witAward = d.ev.t == "AWARD"
  val witExpiredLocked = d.st == EXPIRED and d.wasLocked
  val witRecovered = SLOTS.exists(s => d.slots.get(s).rec == RecDone)
  val witRotated = d.audit.lastRotation.slot != ""
  val witChipRelease = d.fin.done and d.fin.attA.method == Chip

  // ---------- Liveness ----------

  // Every deal ends, if steps keep happening (weak fairness on the whole step).
  temporal ends = weakFair(stepLive, d) implies eventually(d.st == CLOSED)

  // The same property for stepLiveDQ6. It must fail.
  temporal endsDQ6 = weakFair(stepLiveDQ6, d) implies eventually(d.st == CLOSED)

  // ---------- Scenario tests (`quint test spec/deal.qnt`) ----------

  action signAll = all {
    d.prop != NoProp,
    go({ ...d, sigs: SLOTS.map(s => (s, d.slots.get(s).epoch)), ev: NO_EVENT }),
  }

  // A `.fail()` step leaves the next state unset, so every blocked attack ends its own run.

  run toVerifiedTest =
    initWith(PolicyZkOrChip)
      .then(signContract).then(openShell).then(fundQuarantine).then(keysMade(Zk, Chip))
      .then(lockWallet).then(verifyOk)
      .expect(d.st == VERIFIED)

  run toReceivedTest = toVerifiedTest.then(ship).then(receive).expect(d.st == RECEIVED)

  run happyPathTest =
    toReceivedTest
      .then(attest("A", Zk, true)).then(attest("B", Chip, true)).then(evalGate("")).then(release)
      .expect(d == funded(PolicyZkOrChip, Zk, Chip))

  run fullDealTest =
    happyPathTest
      .then(propose(PayBob)).then(slotSign("A")).then(slotSign("LA")).then(slotSign("B")).then(slotSign("LB"))
      .then(submit).expect(d.st == PAID_OUT and d.audit.lastOutSigs == QUORUM)
      .then(propose(CloseAccount)).then(signAll).then(submit)
      .expect(d.st == CLOSED and invAll)

  run disputeAwardTest =
    happyPathTest.then(openDispute).then(propose(RefundAlice)).then(signAll).then(submit)
      .expect(d.st == REFUNDED and d.ev == { t: "AWARD", sigs: QUORUM, gatePassed: false, to: "ALICE" })

  run expiryTest =
    toVerifiedTest.then(cancelAfterPasses).then(escrowCancel)
      .then(propose(CloseAccount)).then(signAll).then(submit)
      .expect(d.st == CLOSED and not(d.fin.done))

  // P5.1-03: plantRegularKey while the master key is on.
  pure def plantedShellLocked(x: Deal): bool = x.st == WALLET_LOCKED and x.ledger.regularKey

  run plantedKey =
    initWith(PolicyZk).then(signContract).then(openShell).then(plantRegularKey)
      .then(fundQuarantine).then(keysMade(Zk, Zk)).then(lockWallet)
      .expect(plantedShellLocked(d))

  run plantRegularKeyBlocksVerifyTest = plantedKey.then(verifyOk.fail())

  run plantedKeyCannotPayTest = plantedKey.then(cancelAfterPasses).then(escrowCancel)
    .expect(d.st == EXPIRED and not(d.ledger.funds))

  run plantAfterLockTest = toVerifiedTest.then(plantRegularKey.fail())

  run plantDelegateAfterLockTest = toVerifiedTest.then(plantDelegate.fail())

  // P5.1-03: singleSignedExit.
  run oneSlotExitTest = initFundedWith(PolicyZk, Zk, Zk).then(submitOut(PayBob, Set(("A", 0)), false, false).fail())

  run masterExitTest = initFundedWith(PolicyZk, Zk, Zk).then(submitOut(PayBob, Set(), true, false).fail())

  run regularKeyExitTest = initFundedWith(PolicyZk, Zk, Zk).then(submitOut(RefundAlice, Set(), false, true).fail())

  run threeSlotExitTest =
    initFundedWith(PolicyZk, Zk, Zk).then(submitOut(PayBob, Set(("A", 0), ("LA", 0), ("B", 0)), false, false).fail())

  // P5.1-03: strangerFinish and skipPassport.
  run strangerFinishTest = toVerifiedTest.then(leakCode).then(strangerFinish.fail())

  run oneAttestation = toReceivedTest.then(attest("A", Zk, true)).then(evalGate(""))

  run skipPassportReleaseTest = oneAttestation.then(release.fail())

  run skipPassportTest = oneAttestation.then(skipPassport.fail())

  run forbiddenMethodTest =
    initWith(PolicyZk).then(signContract).then(openShell).then(fundQuarantine).then(keysMade(Zk, Chip).fail())

  run wrongMethod =
    toReceivedTest.then(attest("A", Zk, true)).then(attest("B", Zk, true)).then(evalGate(""))
      .expect(not(d.gate.get("PASSPORT_B_OK")) and not(d.gate.get("IDENTITY_POLICY_OK")))

  run wrongMethodAtReleaseTest = wrongMethod.then(release.fail())

  // P5.1-08: soloAgentSign and outsidePolicyShare.
  run payProposed = initFundedWith(PolicyZk, Zk, Zk).then(propose(PayBob))

  run soloAgentSignTest = payProposed.then(soloAgentSign("A").fail())

  run outsiderWithPhoneTest = payProposed.then(slotSignWith("A", Set(1, OUTSIDER)).fail())

  run outsiderWithHsmTest = payProposed.then(slotSignWith("LA", Set(2, OUTSIDER)).fail())

  // P5.1-09, P5.1-10, P5.1-13: recovery delay and cancel.
  run phoneLost = payProposed.then(shareLost("A", 1))

  run lostPhoneCannotSignTest = phoneLost.then(slotSign("A").fail())

  run forgedRecoveryStartTest = phoneLost.then(forgedRecoveryStart("A").fail())

  run recoveryAtHourZeroTest = phoneLost.then(recoveryStart("A")).then(slotSignWith("A", Set(2, 3)).fail())

  run earlyRecoverySignTest =
    phoneLost.then(recoveryStart("A")).then(tick).then(tick).then(earlyRecoverySign("A").fail())

  run recoveryTest =
    phoneLost.then(recoveryStart("A")).then(tick).then(tick).then(tick)
      .expect(d.slots.get("A").recHours == DELAY)
      .then(slotSignWith("A", Set(2, 3)))
      .expect(d.slots.get("A").rec == RecDone and invRecoveryDelay)
      .then(shareJoins("A", 1))
      .expect(d.slots.get("A").held == HOLDERS and d.slots.get("A").rec == RecNone)

  run cancelled =
    payProposed.then(shareLost("LB", 2)).then(recoveryStart("LB"))
      .then(tick).then(tick).then(tick).then(recoveryCancel("LB"))

  run signAfterCancelTest = cancelled.then(signAfterCancel("LB").fail())

  run recoveryPairAfterCancelTest = cancelled.then(slotSignWith("LB", Set(1, 3)).fail())

  run twoSharesLostTest =
    payProposed.then(shareLost("B", 1)).then(shareLost("B", 2))
      .then(recoveryStart("B")).then(tick).then(tick).then(tick)
      .then(slotSignWith("B", Set(2, 3)).fail())

  // P5.1-11, P5.1-13: rotation.
  run rotationProposed =
    initFundedWith(PolicyZk, Zk, Zk)
      .then(compromiseShare("LA")).then(refresh("LA"))
      .expect(d.slots.get("LA").unsafe)
      .then(propose(Rotate("LA")))

  run rotateWithoutOneSlotTest = rotationProposed.then(rotateWithoutOneSlot("LA").fail())

  run rotated =
    rotationProposed.then(signAll).then(submit)
      .expect(d.slots.get("LA").epoch == 1 and not(d.slots.get("LA").unsafe) and invRotateNeedsAll)

  run staleEpochSignTest = rotated.then(propose(PayBob)).then(signAll).then(staleEpochSign("LA")).then(submit.fail())

  // P5.1-03, I5: the second exit candidate does not pay out after the first.
  run secondCandidateTest =
    initFundedWith(PolicyZk, Zk, Zk).then(propose(PayBob)).then(signAll).then(submit)
      .then(submitOut(RefundAlice, SLOTS.map(s => (s, 0)), false, false).fail())

  run oldKeysExitTest = rotated.then(submitOut(PayBob, SLOTS.map(s => (s, 0)), false, false).fail())
}
