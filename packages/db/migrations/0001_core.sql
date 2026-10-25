-- DESIGN 9: the data model. Source: DESIGN.md section 9, with the changes recorded in packages/db/SOURCES.md.
-- Source: https://www.postgresql.org/docs/18/sql-createtrigger.html (BEFORE UPDATE/DELETE row triggers, BEFORE TRUNCATE statement triggers)
-- Source: https://www.postgresql.org/docs/18/sql-revoke.html

-- The application role. Roles are cluster-wide, so create it only when it is missing.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_rw') THEN CREATE ROLE app_rw NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA public TO app_rw;

CREATE TABLE deal (
  deal_id        uuid PRIMARY KEY DEFAULT uuidv7(),
  state          text NOT NULL CHECK (state IN ('DRAFT','CONTRACT_SIGNED','SHELL_OPEN','QUARANTINED',
                   'KEYS_READY','WALLET_LOCKED','VERIFIED','FUNDED','PAID_OUT','REFUNDED','DISPUTED','EXPIRED','CLOSED')),
  was_locked     boolean NOT NULL DEFAULT false,
  network        text NOT NULL CHECK (network IN ('standalone','testnet','devnet','mainnet')),
  contract_root  bytea NOT NULL CHECK (length(contract_root) = 32),
  deal_seal      bytea CHECK (length(deal_seal) = 32),
  shell_address  text,
  signed_contract_seal bytea CHECK (length(signed_contract_seal) = 32),
  nft_token_id   text,
  mint_tx_hash   text,
  lawyer_ops_a   text,
  lawyer_ops_b   text,
  escrow_owner   text, escrow_sequence bigint,
  condition_hex  text,
  cancel_after   bigint,
  exit_slot      bigint,
  payout_a       text NOT NULL,
  payout_b       text NOT NULL,
  -- DESIGN 9 writes `releaser_account IS NULL OR releaser_account = lawyer_ops_b`, which passes when lawyer_ops_b is NULL
  -- (NULL comparison). IS NOT DISTINCT FROM closes that hole.
  releaser_account text,
  amount_drops   numeric(20,0) NOT NULL CHECK (amount_drops >= 0),
  created_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT deal_releaser_is_ops_b CHECK (releaser_account IS NULL OR releaser_account IS NOT DISTINCT FROM lawyer_ops_b)
);

CREATE TABLE deal_key (
  deal_id     uuid NOT NULL REFERENCES deal,
  role        text NOT NULL CHECK (role IN ('alice','lawyerA','bob','lawyerB')),
  xrpl_pubkey text NOT NULL CHECK (xrpl_pubkey ~ '^ED[0-9A-F]{64}$'),
  xrpl_account text NOT NULL,
  commitment  bytea NOT NULL CHECK (length(commitment) = 32),
  binding_sig bytea NOT NULL CHECK (length(binding_sig) = 64),
  slot_policy  bytea NOT NULL CHECK (length(slot_policy) = 32),
  pq_key_hash  bytea NOT NULL CONSTRAINT deal_key_pq_key_hash_32 CHECK (length(pq_key_hash) = 32),
  pq_binding_sigs jsonb NOT NULL CONSTRAINT deal_key_pq_binding_sigs_two CHECK (
    jsonb_typeof(pq_binding_sigs) = 'array' AND jsonb_array_length(pq_binding_sigs) = 2
    AND (pq_binding_sigs -> 0) ?& ARRAY['key_id','sig'] AND (pq_binding_sigs -> 1) ?& ARRAY['key_id','sig']),
  pq_cross_sig   bytea NOT NULL CHECK (length(pq_cross_sig) = 64),
  id_method    text CONSTRAINT deal_key_id_method CHECK (id_method IN ('zkpassport','nfc-chip')),
  contract_sig bytea CHECK (length(contract_sig) = 64),
  ops_account  text,
  ops_bind_sig_ops    bytea CHECK (length(ops_bind_sig_ops) BETWEEN 64 AND 72),
  ops_bind_sig_lawyer bytea CHECK (length(ops_bind_sig_lawyer) = 64),
  PRIMARY KEY (deal_id, role),
  CONSTRAINT deal_key_lawyer_fields CHECK ((role IN ('lawyerA','lawyerB')) =
    (contract_sig IS NOT NULL AND ops_account IS NOT NULL AND ops_bind_sig_ops IS NOT NULL AND ops_bind_sig_lawyer IS NOT NULL)),
  -- DESIGN 9: id_method is for clients only. Lawyers carry the lawyer fields, clients carry id_method.
  CONSTRAINT deal_key_id_method_clients_only CHECK ((role IN ('alice','bob')) = (id_method IS NOT NULL))
);

CREATE TABLE lawyer (
  ops_account   text PRIMARY KEY,
  jurisdiction  text NOT NULL,
  bar_number_sha256 bytea NOT NULL CHECK (length(bar_number_sha256) = 32)
);
CREATE TABLE bar_verification (
  envelope_sha256 bytea PRIMARY KEY CHECK (length(envelope_sha256) = 32),
  ops_account   text NOT NULL REFERENCES lawyer,
  envelope      bytea NOT NULL,
  status        text NOT NULL CHECK (status IN ('active','not_active')),
  checked_at_ledger bigint NOT NULL,
  checked_at_ledger_hash text NOT NULL
);
CREATE TABLE attorney_credential (
  ops_account   text NOT NULL REFERENCES lawyer,
  verification_sha256 bytea NOT NULL REFERENCES bar_verification,
  create_tx_hash text NOT NULL, accept_tx_hash text,
  expiration    bigint NOT NULL,
  PRIMARY KEY (ops_account, create_tx_hash)
);
CREATE TABLE bar_deal_link (
  deal_id  uuid NOT NULL REFERENCES deal,
  role     text NOT NULL CHECK (role IN ('lawyerA','lawyerB')),
  envelope bytea NOT NULL,
  verification_sha256 bytea NOT NULL REFERENCES bar_verification,
  PRIMARY KEY (deal_id, role, verification_sha256)
);
-- Never holds passport data (DESIGN 9).
CREATE TABLE passport_attestation (
  deal_id  uuid NOT NULL REFERENCES deal,
  side     text NOT NULL CHECK (side IN ('A','B')),
  envelope bytea NOT NULL,
  anchor_ledger bigint NOT NULL,
  leaf_hash bytea NOT NULL UNIQUE CHECK (length(leaf_hash) = 32),
  PRIMARY KEY (deal_id, side, leaf_hash)
);
CREATE TABLE zk_proof (
  deal_id  uuid NOT NULL REFERENCES deal,
  side     text NOT NULL CHECK (side IN ('A','B')),
  stage    text NOT NULL CHECK (stage IN ('onboarding','release')),
  proof    bytea NOT NULL,
  registry_roots jsonb NOT NULL CHECK (jsonb_typeof(registry_roots) = 'object'),
  identifier_hash bytea NOT NULL CHECK (length(identifier_hash) = 32),
  PRIMARY KEY (deal_id, side, stage, identifier_hash)
);

-- Evidence first: enrollment_key cites the event that records the key hash (DESIGN 6.3, task 3.1 P3.1-14).
CREATE TABLE evidence_event (
  event_id   uuid PRIMARY KEY DEFAULT uuidv7(),
  deal_id    uuid NOT NULL,
  seq        bigint NOT NULL CHECK (seq >= 0),
  prev_hash  bytea NOT NULL CHECK (length(prev_hash) = 32),
  envelope   bytea NOT NULL CHECK (length(envelope) > 0),
  leaf_hash  bytea NOT NULL CONSTRAINT evidence_event_leaf_hash_key UNIQUE CHECK (length(leaf_hash) = 32),
  received_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT evidence_event_deal_id_seq_key UNIQUE (deal_id, seq)
);
CREATE TABLE evidence_log_entry (
  event_id  uuid PRIMARY KEY REFERENCES evidence_event,
  log_index bigint NOT NULL UNIQUE CHECK (log_index >= 0)
);

-- DESIGN 6.3 lists no deal_id and no evidence link; 8.10 and P3.1-12 and P3.1-14 need both (see SOURCES.md, design questions).
CREATE TABLE enrollment_key (
  key_id   text PRIMARY KEY,
  deal_id  uuid NOT NULL REFERENCES deal,
  slot     text NOT NULL CHECK (slot IN ('A','LA','B','LB')),
  holder_role text NOT NULL CHECK (holder_role IN ('phone','security-key','second-device','passkey-same-device',
                   'recovery-agent','console','firm-hsm','partner')),
  ed25519_pub bytea NOT NULL CHECK (length(ed25519_pub) = 32),
  mldsa65_pub bytea NOT NULL CHECK (length(mldsa65_pub) = 1952),
  valid_from bigint NOT NULL,
  valid_to   bigint,
  evidence_event_id uuid NOT NULL REFERENCES evidence_event,
  CONSTRAINT enrollment_key_holder_keys_key UNIQUE (deal_id, slot, holder_role, ed25519_pub, mldsa65_pub)
);
CREATE INDEX enrollment_key_holder_idx ON enrollment_key (deal_id, slot, holder_role);

CREATE TABLE release_gate (
  deal_id  uuid NOT NULL REFERENCES deal,
  leaf_hash bytea PRIMARY KEY CHECK (length(leaf_hash) = 32),
  envelope bytea NOT NULL,
  ledger_index bigint NOT NULL
);

CREATE TABLE signature_request (
  request_id  uuid PRIMARY KEY DEFAULT uuidv7(),
  deal_id     uuid NOT NULL REFERENCES deal,
  purpose     text NOT NULL,
  unsigned_tx jsonb NOT NULL,
  last_ledger bigint NOT NULL,
  status      text NOT NULL DEFAULT 'open'
);
CREATE TABLE signature (
  request_id  uuid NOT NULL REFERENCES signature_request,
  role        text NOT NULL,
  signer_blob text NOT NULL,
  PRIMARY KEY (request_id, role)
);

CREATE TABLE ledger_observation (
  tx_hash bytea PRIMARY KEY CHECK (length(tx_hash) = 32), ledger_index bigint NOT NULL, tx_index int NOT NULL,
  account text NOT NULL, tx_type text NOT NULL, result text NOT NULL, meta jsonb NOT NULL
);
CREATE TABLE watcher_cursor (account text PRIMARY KEY, last_validated_ledger bigint NOT NULL);
CREATE TABLE outbox (id uuid PRIMARY KEY DEFAULT uuidv7(), topic text NOT NULL, payload bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), sent_at timestamptz);
CREATE TABLE checkpoint_anchor (
  tree_size bigint PRIMARY KEY, root bytea NOT NULL CHECK (length(root) = 32), checkpoint bytea NOT NULL,
  anchor_tx_hash text, anchor_ledger bigint, rfc3161_token bytea
);

GRANT SELECT, INSERT, UPDATE, DELETE ON
  deal, deal_key, lawyer, bar_verification, attorney_credential, bar_deal_link, passport_attestation, zk_proof,
  evidence_event, evidence_log_entry, enrollment_key, release_gate, signature_request, signature,
  ledger_observation, watcher_cursor, outbox, checkpoint_anchor
TO app_rw;

-- Append-only pattern (DESIGN 8.9): REVOKE for the role, plus triggers that also stop the owner and superusers.
-- legx_make_append_only is reused by later migrations, so it stays in the schema.
CREATE FUNCTION deny_mut() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'append-only'; END$$;
CREATE FUNCTION legx_make_append_only(t regclass) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %s FROM app_rw', t);
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION deny_mut()',
                 replace(t::text, '"', '') || '_immutable', t);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION deny_mut()',
                 replace(t::text, '"', '') || '_no_truncate', t);
END $$;

SELECT legx_make_append_only(t) FROM unnest(ARRAY['evidence_event','evidence_log_entry','bar_verification',
  'attorney_credential','bar_deal_link','passport_attestation','release_gate','zk_proof','enrollment_key']::regclass[]) AS t;
