# Cleanup C1b
State: partial (deadline).
Done: I-1 (build0c in @legx/xrpl, verifier uses it, snapshot 0c added), I-W-18 (ci.yml: env vars, named legx-pg container, system job), I-6 wontfix (core tree is array-based; storage needs tile-hash-based).
Tests: xrpl unit 180 pass, 3 timeouts under load (multisig sort, submit property, builders property: 5s timeout); baseline had 4 failures from the same load timeouts.
Not done: I-7, I-18, I-19, I-D-6, frost helper dedupe in xrpl/test-int, knip/jscpd/depcruise, integration/differential/py-ref before/after, line counts. Baseline lines before: xrpl 10344, fixtures 2199, db 2793, signer 657, storage 1377, observability 1040, tools+spec+.github 5378.
Note: edited services/verifier (C2b lane) minimally for I-1.
