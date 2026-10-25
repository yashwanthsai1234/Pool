# Sources (@legx/xrpl)

- https://xrpl.org/docs/infrastructure/testing-and-auditing/run-private-network-with-docker : the `rippleci/xrpld` standalone container and config mount.
- https://github.com/XRPLF/xrpl.js/blob/main/.ci-config/xrpld.cfg : the standalone config (`ci/xrpld.cfg`): `[features]`, `[voting]` fees and reserves.
- https://xrpl.org/docs/infrastructure/testing-and-auditing/start-a-new-genesis-ledger-in-stand-alone-mode : genesis account, ledger 1.
- https://xrpl.org/docs/references/http-websocket-apis/admin-api-methods/server-control-methods/ledger_accept : closing ledgers by hand.
- https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/test/integration/utils.ts : `waitForAndForceProgressLedgerTime` (advanceCloseTime).
- https://xrpl.org/docs/references/http-websocket-apis/admin-api-methods/status-and-debugging-methods/feature : the `feature` method (`enabled`, `vetoed: "Obsolete"`).
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/simulate : non-mutating probe for Credentials (`temDISABLED`).
- https://xrpl.org/resources/known-amendments : retired amendments.
- https://xrpl.org/docs/infrastructure/testing-and-auditing/test-amendments : enabling amendments on a test node.
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/server-info-methods/server_info : fees, reserves, `network_id`, peers.
- https://xrpl.org/docs/concepts/networks-and-servers/parallel-networks : network ids and Testnet/Devnet endpoints.
- Research notes r5-xrpl.md (scratchpad), section 3: faucet API (`POST https://faucet.altnet.rippletest.net/accounts`, 1000 XRP cap, no documented rate limit).
- DESIGN.md sections 7.1, 11.2, 11.3 and Appendix B.
- (2.3) https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/models/transactions/CredentialCreate.ts and CredentialAccept.ts, NFTokenMint.ts, accountSet.ts, depositPreauth.ts, signerListSet.ts, ticketCreate.ts, escrow*.ts, common.ts (`validate` rules, memo and hex checks): what `validate()` enforces per builder (xrpl 5.3.0, read in node_modules).
- (2.3) https://xrpl.org/docs/references/protocol/transactions/types/{credentialcreate,credentialaccept,nftokenmint,escrowcreate,escrowfinish,escrowcancel,accountset,signerlistset,depositpreauth,ticketcreate,accountdelete,payment}: field lists per row of DESIGN 7.3.
- (2.3) https://xrpl.org/docs/references/protocol/transactions/common-fields : Memos (1 KB), Fee, Sequence/TicketSequence, LastLedgerSequence, NetworkID.
- (2.3) https://xrpl.org/docs/concepts/accounts/addresses#x-addresses : X-address (Mainnet `X`, test `T`) refusal.
- (2.3) https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/client/index.ts : `autofill` fills only absent Sequence/Fee/LastLedgerSequence; 1.2x cushion applies only when Fee is absent (sugar/getFeeXrp.ts).

## Task 2.2 (reliable submission and one-ledger reads: `src/submit.ts`, `src/read.ts`)

- https://xrpl.org/docs/concepts/transactions/reliable-transaction-submission : the submit and verify loop; a missing transaction is final only with LastLedgerSequence passed and continuous history; resubmitting the same blob is safe; reconcile with `account_tx` by sequence.
- https://xrpl.org/docs/concepts/transactions/finality-of-results/transaction-malleability : a multisigned copy can validate under another hash; track the account Sequence, not the hash.
- https://xrpl.org/docs/references/protocol/transactions/transaction-results : result classes; immediate results are provisional; tef "may already have been applied".
- https://xrpl.org/docs/references/protocol/transactions/transaction-results/tef-codes : tefPAST_SEQ, tefALREADY, tefMAX_LEDGER, tefNO_TICKET and the other tef codes.
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/tx : `min_ledger`/`max_ledger` (at most 1000 apart, `excessiveLgrRange`), `txnNotFound`, `searched_all`, API v2 shape (`tx_json`, `meta`, `hash`, `ledger_index`, `validated`).
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_tx : `binary` entries (`tx_blob`, `meta_blob`, no hash in v2), `forward`, `marker`, ordered pages.
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_info and .../account_objects : reads pinned to one `ledger_index`.
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/ledger-methods/ledger_entry#get-ticket-object : ticket lookup.
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/ledger-methods/ledger : ledger header (hash, close_time).
- https://xrpl.org/docs/references/http-websocket-apis/api-conventions/markers-and-pagination : always follow `marker`.
- https://xrpl.org/docs/concepts/payment-types/partial-payments and https://xrpl.org/docs/references/protocol/transactions/metadata#delivered_amount : read `delivered_amount`, never `Amount`.
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/server-info-methods/server_info : `validated_ledger.seq`, `complete_ledgers`.
- xrpl.js 5.3.0 `dist/npm/client/connection.js` (read in node_modules): automatic reconnect on an unexpected close; `ConnectionError` subclasses for dropped sockets.
- fast-check 4.10.2 `fc.scheduler()` / `scheduleFunction` / `waitFor` (read in node_modules): the WebSocket fault test.
- Measured on xrpld 3.4.1 standalone (`build/tmp/2.2/probe.ts`, `gap.ts`): see `build/status/2.2.md`.

## Task 2.4 (multisig collection and exit slot S: `src/multisig.ts`)

- https://xrpl.org/docs/concepts/accounts/multi-signing : signer list, quorum, Signers array rules.
- https://xrpl.org/docs/references/protocol/transactions/common-fields#signers-field : Signers sorted by AccountID bytes.
- https://xrpl.org/docs/concepts/accounts/tickets : Ticket slot (Sequence 0 plus TicketSequence), `tefNO_TICKET`.
- https://xrpl.org/docs/references/protocol/transactions/types/ticketcreate : 4-of-4 TicketCreate.
- fast-check 4.10.2 `scheduledModelRun`, `shuffledSubarray`, `commands` (read in node_modules): the race test.

## Task 2.5 (full flows: `test-int/roles.ts`, `test-int/full-flow.int.test.ts`)

- DESIGN.md 5.2, 5.3, 5.4, 7.3 : the phases, steps and transactions of the flow.
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/tx : binary `tx_blob` for the gate's mint check, `meta.nftoken_id`.
- https://xrpl.org/docs/references/protocol/transactions/types/depositpreauth : `Unauthorize` (the replaced releaser, T-I-10).
- https://xrpl.org/docs/references/protocol/transactions/types/accountdelete : 256-ledger wait, fee of one owner reserve.
- https://www.rfc-editor.org/rfc/rfc9562 : UUID version 7 for deal and event IDs.

## Task 2.7 (watcher client, `src/watcher/`)
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/subscription-methods/subscribe : `accounts` and `ledger` streams; `accounts_proposed` includes unfinished transactions and is never used; `transaction` messages carry `validated`.
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_tx : `forward`, `ledger_index_min`/`max` (-1 = earliest / latest validated), `marker` paging.
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/ledger-methods/ledger : `ledger_hash` of a validated ledger, `lgrNotFound`; compared across servers.
- https://xrpl.org/docs/references/http-websocket-apis/api-conventions/markers-and-pagination : always follow `marker`.
- Measured on xrpld 3.4.1 standalone (`build/tmp/2.7/probe.ts`): stream message keys, `account_tx` v2 shape, `ledger_index_min` below the earliest ledger gives `lgrIdxMalformed`, `-1` is accepted.
