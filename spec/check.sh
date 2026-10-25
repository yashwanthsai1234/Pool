#!/bin/sh
# Long checks for the Quint model (task 5.1, T-F-01). The short ones run in spec/test/quint.test.ts.
# Usage: spec/check.sh [run|apalache|apalache-sim|tlc|tlc-safety|traces|all]
# Needs Java 17 or later. Quint downloads Apalache (about 190 MB) and its Rust evaluator (about 2 MB)
# into ~/.quint (or $QUINT_HOME) on first use. TLC comes inside the Apalache jar.
# Sources: https://quint.sh/docs/quint  https://quint.sh/docs/model-checkers
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$ROOT/.tools/node/bin:$PATH"
QUINT="$ROOT/node_modules/@informalsystems/quint/dist/src/cli.js"
SPEC="$ROOT/spec/deal.qnt"
TLC_CONFIG="$ROOT/spec/tlc.json"
INVARIANTS="invLockedBeforeFunds invFourSigs invGateBeforeFunds invOneExit invClosedFinal invTwoPassports invTwoShares invRecoveryDelay invRotateNeedsAll invOldKeyDead invUnsafeUntilRotated"
APALACHE_STEPS="${APALACHE_STEPS:-10}"
TRACES_OUT="${TRACES_OUT:-$ROOT/build/tmp/5.1/traces}"

# Apalache writes _apalache-out into the working directory, so work in a temporary one.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

q() { node "$QUINT" "$@"; }

# T-F-01a: 10,000 random runs of 30 steps, every invariant.
run_sim() {
  # shellcheck disable=SC2086
  q run "$SPEC" --step stepSim --invariants $INVARIANTS --max-steps 30 --max-samples 10000 \
    --witnesses witReleased witClosedAfterExit witAward witExpiredLocked witRecovered witRotated witChipRelease
  # shellcheck disable=SC2086
  q run "$SPEC" --init initFunded --step stepSim --invariants $INVARIANTS --max-steps 30 --max-samples 10000 \
    --witnesses witClosedAfterExit witAward witRecovered witRotated
}

# T-F-01b: Apalache, bounded. Every transition sequence up to APALACHE_STEPS, from init and from FUNDED.
run_apalache() {
  q verify "$SPEC" --invariant invAll --max-steps "$APALACHE_STEPS"
  q verify "$SPEC" --init initFunded --invariant invAll --max-steps "$APALACHE_STEPS"
}

# T-F-01b, symbolic simulation: Apalache picks random transitions for 30 steps and solves all data
# choices symbolically, 100 runs each (the Apalache default).
run_apalache_sim() {
  q verify "$SPEC" --invariant invAll --random-transitions --max-steps 30
  q verify "$SPEC" --init initFunded --invariant invAll --random-transitions --max-steps 30
}

# T-F-01c: "eventually CLOSED" under weak fairness, with TLC. Then the same with two shares of one
# slot lost, which must fail (DQ-6): the script fails if TLC does not find that counterexample.
run_tlc() {
  q verify "$SPEC" --backend tlc --tlc-config "$TLC_CONFIG" --step stepLive --temporal ends
  if q verify "$SPEC" --backend tlc --tlc-config "$TLC_CONFIG" --step stepLiveDQ6 --temporal endsDQ6; then
    echo "expected endsDQ6 to fail: two lost shares must block the deal" >&2
    exit 1
  fi
}

# Every invariant over the whole liveness state space, with TLC (exhaustive, not bounded).
run_tlc_safety() {
  q verify "$SPEC" --backend tlc --tlc-config "$TLC_CONFIG" --step stepLive --invariant invAll
}

# 1,000 random traces in ITF, for the conformance replay through machine.ts (after task 1.14).
run_traces() {
  mkdir -p "$TRACES_OUT"
  q run "$SPEC" --step stepSim --max-steps 30 --max-samples 1000 --n-traces 1000 \
    --out-itf "$TRACES_OUT/trace_{seq}.itf.json"
}

case "${1:-all}" in
  run) run_sim ;;
  apalache) run_apalache ;;
  apalache-sim) run_apalache_sim ;;
  tlc) run_tlc ;;
  tlc-safety) run_tlc_safety ;;
  traces) run_traces ;;
  all) q typecheck "$SPEC"; q test "$SPEC"; run_sim; run_apalache_sim; run_apalache; run_tlc; run_tlc_safety; run_traces ;;
  *) echo "usage: $0 [run|apalache|apalache-sim|tlc|tlc-safety|traces|all]" >&2; exit 2 ;;
esac
