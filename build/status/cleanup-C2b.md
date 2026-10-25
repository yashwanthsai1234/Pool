# Cleanup C2b
State: stopped at deadline. NO code changes made; lane is unchanged (9710 lines before and after).
Baseline unit run (services/{evidence,verifier,zk-verifier,renewal,watcher}, apps/mock-bar-registry): killed (exit 144) under machine load; the failures seen (evidence pq checkpoint/hybrid tests) were 12-16 s timeouts, not code failures. No integration baseline taken. No containers started.
## Not done
- I-2 (XA-DEMO -> XA-DM), I-12 (pq.bound attachment + SHA-256), I-13, I-15, I-3.7-e (evidence half; C2's status file did not exist, so no key-id convention to follow).
- knip, jscpd, dependency-cruiser, dead-code and duplication passes.
