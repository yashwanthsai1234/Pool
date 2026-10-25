# Quint model of the deal (task 5.1, T-F-01)

`deal.qnt` models the deal wallet of DESIGN 5.1 with the FROST slots of 6.4, the identity method
and policy of 6.10 and 6.15, and the release gate of 6.17. It grew from the sketch in DESIGN
Appendix C, which was never run.

## What is in the model

| Part | How it is modelled | DESIGN |
|---|---|---|
| States | `DRAFT` ... `CLOSED`, the same names as `packages/core/src/machine.ts` | 5.1 |
| Ledger | master key, regular key, delegate, quorum, DepositAuth with one preauth, escrow, funds. The ledger rules decide every submitted transaction (`ledgerAccepts`, `multisigOk`, `finishAccepted`) | 6.8, 6.9, D4 |
| Slots | per slot: the holders still holding a share (`held`, 0 to 3), the key epoch, the recovery state (`RecNone`, `RecPending`, `RecCancelled`, `RecDone`) with a clock in hours, `unsafe` after a stolen share | 6.4 |
| Signing | `slotSignWith(slot, signers)`: shares that are not from a current holder are dropped; 2 are needed; any pair with holder 3 (recovery agent or partner) is the recovery path and needs the 72-hour delay without a cancel | 6.4 |
| Rotation | `Rotate(slot)` is a 4-of-4 transaction: new DKG, new signer list entry (next epoch), new seal, and for a lawyer slot a new contract signature and NFT | 6.4 |
| Identity | `policy` (`zk`, `zk-or-chip`, `chip`), the onboarding method of each client, and the release attestation of each client (present, valid, method) | 6.10, 6.15 |
| Release gate | `gate`: one boolean per check of the 6.17 table (15). `LOCK_OK`, `RELEASER_SEALED`, `PASSPORT_A_OK`, `PASSPORT_B_OK` and `IDENTITY_POLICY_OK` are computed from the model state; the other ten are evidence the model does not track, so the environment may fail any one of them | 6.17 |
| Faults | lost share, failed or expired passport check, failing gate check, cancelled recovery, stolen share; at most `MAX_FAULTS` (3) per run, so TLC sees a finite state space | 5.4 |
| Attacks | `plantRegularKey`, `plantDelegate`, `leakCode` with `strangerFinish`, `singleSignedExit` (one slot, the master key, or a planted regular key), `skipPassport`, `replayCandidate` (the second signed exit candidate), `soloAgentSign`, `outsidePolicyShare`, `earlyRecoverySign`, `signAfterCancel`, `forgedRecoveryStart` (no identity proof), `staleEpochSign`, `rotateWithoutOneSlot` | 10.1 |

Attacker actions call the same acceptance logic as the honest actions, with hostile inputs. So an
attack can only succeed if a guard is missing, and the mutation tests show what happens then.

### Invariants

| Name | Rule | Test |
|---|---|---|
| `invLockedBeforeFunds` | I1, I3: funds enter only a locked wallet (master off, quorum 4, no regular key, no delegate), and it stays locked | T-F-01a, b |
| `invFourSigs` | I2: every outflow after the lock carries four signatures | T-F-01a, b |
| `invGateBeforeFunds` | I8: funds enter only through lawyer B's release, after every gate check passed | T-F-01a, b, P5.1-02 |
| `invOneExit` | I5: at most one exit | T-F-01a, b |
| `invClosedFinal` | I6: `CLOSED` is final | T-F-01a, b |
| `invTwoPassports` | no release without two present, valid attestations, each of a method the policy allows | P5.1-06, P5.1-07 |
| `invTwoShares` | a slot signature always comes from at least 2 valid shares of a slot holding at least 2 | P5.1-05, P5.1-07 |
| `invRecoveryDelay` | a recovery signature comes at least 72 hours after the start, and never after a cancel | P5.1-10, P5.1-12 |
| `invRotateNeedsAll` | a rotation is signed by all four slots, with a new seal, and a new NFT for a lawyer slot | P5.1-11, P5.1-12 |
| `invOldKeyDead` | after a rotation, a key of the old epoch never signs an accepted transaction | P5.1-11, P5.1-12 |
| `invUnsafeUntilRotated` | a refresh alone never makes a compromised slot safe | P5.1-11 |
| `invAll` | all of the above | |

`temporal ends`: under weak fairness of `stepLive`, every deal eventually reaches `CLOSED` (T-F-01c).
`temporal endsDQ6` adds the loss of a second share of one slot and must fail: the money then waits
for arbitration (DESIGN 6.4, DQ-6).

## Commands

Run from the repository root, with `export PATH="$PWD/.tools/node/bin:$PATH"`.

```sh
pnpm exec quint typecheck spec/deal.qnt                       # P5.1-01
pnpm exec quint test spec/deal.qnt                            # 33 scenario runs: P5.1-03, -04, -08, -09, -11, -13
pnpm vitest run --config spec/vitest.config.ts                # the CI checks below, about 2 minutes
spec/check.sh run           # T-F-01a: quint run, 30 steps, 10,000 samples, from init and from FUNDED
spec/check.sh apalache-sim  # T-F-01b: Apalache symbolic simulation, 30 steps, 100 runs each
spec/check.sh apalache      # T-F-01b: Apalache bounded check, from init and from FUNDED (APALACHE_STEPS, default 10)
spec/check.sh tlc           # T-F-01c: TLC, eventually CLOSED under fairness; and endsDQ6 must fail
spec/check.sh tlc-safety    # every invariant over the whole stepLive state space, with TLC
spec/check.sh traces        # 1,000 ITF traces into build/tmp/5.1/traces, for the replay after task 1.14
```

The Vitest file `spec/test/quint.test.ts` runs: `typecheck`; `quint test`; three short `quint run`
checks of every invariant (300 samples, 30 steps); a witness check that the runs reach release,
award, recovery, chip release and expiry; 14 model mutations, each of which must break its
invariant with a printed counterexample (P5.1-02, P5.1-07, P5.1-12, and one each for I1, I2, I3,
I5, I6 and the refresh rule); and the ITF export. The conformance replay through `machine.ts` is
`it.todo` until task 1.14.

Steps: `step` is every behaviour (Apalache checks it). `stepSim` has the same branches, with the
honest step listed eight times, because the simulator picks uniformly among enabled branches and
would otherwise rarely get past the release in 30 steps. `initFunded` starts right after the
release; `happyPathTest` shows `init` reaches exactly that state.

## Tools and setup

- **Quint 0.33.0** is a root devDependency. `quint run` uses the Rust evaluator, which Quint
  downloads on first use into `~/.quint/rust-evaluator-v0.7.0` (2.3 MB).
- **Apalache 0.62.1** (the Quint 0.33.0 default) is downloaded on the first `quint verify` into
  `~/.quint/apalache-dist-0.62.1` (192 MB). Set `QUINT_HOME` to move it. It needs Java 17 or later
  (Java 24 works).
- **TLC** is not a separate download: Quint runs `tlc2.TLC` from the Apalache jar, after Apalache
  translates the model to TLA+ (so run one Apalache `verify` first on a new machine). Quint passes
  `-deadlock`, so TLC does not report deadlocks; the liveness property catches a deal that gets stuck.
  `spec/tlc.json` sets the JVM heap (4 GB), stack and workers.
- Fairness is part of the temporal formula (`weakFair(stepLive, d) implies ...`): the TLC
  configuration that Quint writes has only `INIT`, `NEXT` and `PROPERTY`.
- Apalache runs as a server on port 8822 and writes `_apalache-out/` into the working directory.
  `check.sh` and the tests work in a temporary directory. Do not run two `quint verify` commands at
  once: they share the server, and the first to finish stops it.

## Limits of the model

- **Bounds.** At most 3 faults per run, one rotation per slot, the clock in 24-hour ticks. Liveness
  uses 1 fault per behaviour (823,014 states, about 2 minutes); with 2 the state space passes 7
  million states.
- **Apalache.** A full bounded check grows fast with depth: 8 steps 139 s, 10 steps
  771 s on a laptop, so 30 steps is out of reach. `check.sh apalache` checks every transition
  sequence of 10 steps from `init` and from `initFunded` (FUNDED plus 10 steps reaches the exits,
  recovery and rotation). `check.sh apalache-sim` covers 30 steps by symbolic simulation (random
  transitions, all data choices solved symbolically), about 20 s per run, 100 runs each.
- **The gate is trusted to run.** The ledger cannot see the gate. A dishonest lawyer B who sends the
  `EscrowFinish` outside the console is not modelled: I8 is enforced by the console (DESIGN D4 notes
  the money still lands in a wallet that needs all four keys).
- **The release code** is secret before the lock (`leakCode` is enabled only after it).
- **One gate failure stands for many.** The gate guard is a conjunction, so a run where several
  evidence checks fail at once blocks the same way as one where a single check fails.
- **Rotation** happens only in `FUNDED` and `DISPUTED`, as one step.

## Sources

See `SOURCES.md`.
