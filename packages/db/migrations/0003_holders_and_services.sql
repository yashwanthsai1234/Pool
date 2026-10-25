-- Fix fleet, lane F1 (I-21, I-26, I-3.7-a): the OD-17 holder roles, the outbox NOTIFY, the presence relay, and the
-- tables of the FROST relay, the recovery agent and the firm co-signer, which their services used to create at start.

-- OD-17: role names as in DESIGN 6.4. `second-authenticator` replaces `security-key` and `second-device`.
ALTER TABLE enrollment_key DROP CONSTRAINT enrollment_key_holder_role_check;
ALTER TABLE enrollment_key ADD CONSTRAINT enrollment_key_holder_role_check CHECK (holder_role IN (
  'phone', 'second-authenticator', 'passkey-same-device', 'recovery-agent', 'console', 'firm-hsm', 'partner'));

-- I-3.7-a: one NOTIFY per committed outbox row; the payload is the deal id, or the topic for rows without a deal.
-- NOTIFY is delivered at commit, so a listener that wakes always finds the row.
-- Source: https://www.postgresql.org/docs/current/sql-notify.html
CREATE FUNCTION outbox_notify() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_notify('legx_outbox', COALESCE(NEW.deal_id::text, NEW.topic)); RETURN NEW; END $$;
CREATE TRIGGER outbox_notify AFTER INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION outbox_notify();

-- Passport presence (DESIGN 6.15): the lawyer's open request per side, and the client's signature once given.
CREATE TABLE presence_request (
  deal_id      uuid NOT NULL REFERENCES deal,
  side         text NOT NULL CHECK (side IN ('A', 'B')),
  method       text NOT NULL CHECK (method IN ('zkpassport', 'nfc-chip')),
  lawyer_nonce text NOT NULL CHECK (lawyer_nonce ~ '^[0-9a-f]{64}$'),
  ledger_hash  text NOT NULL CHECK (ledger_hash ~ '^[0-9A-F]{64}$'),
  ledger_index bigint NOT NULL,
  signature    text CHECK (signature ~ '^[0-9a-f]{128}$'),
  PRIMARY KEY (deal_id, side)
);

-- The FROST relay's queue (task 3.9): the exact signed messages, never a nonce or an opened share.
CREATE TABLE frost_relay_session (
  session_id   text PRIMARY KEY,
  deal_id      text NOT NULL,
  slot         text NOT NULL,
  purpose      text NOT NULL,
  participants jsonb NOT NULL,
  status       text NOT NULL,
  attempt      integer NOT NULL,
  parent       text,
  pair         jsonb,
  deadline_ms  bigint,
  next_seq     integer NOT NULL DEFAULT 0
);
CREATE TABLE frost_relay_message (
  session_id text NOT NULL REFERENCES frost_relay_session (session_id),
  seq        integer NOT NULL,
  kind       text NOT NULL,
  from_id    text NOT NULL,
  to_id      text NOT NULL,
  signed     jsonb NOT NULL,
  PRIMARY KEY (session_id, seq),
  UNIQUE (session_id, kind, from_id, to_id)
);

-- A server holder's share store (DESIGN 6.4): one AES-256-GCM sealed share per (deal, slot). Same shape for the
-- recovery agent and the firm HSM; each service has its own table (and in production its own database).
CREATE TABLE recovery_agent_share (
  deal_id text NOT NULL, slot text NOT NULL, epoch integer NOT NULL, group_pub text NOT NULL,
  nonce bytea NOT NULL, ciphertext bytea NOT NULL, PRIMARY KEY (deal_id, slot)
);
CREATE TABLE firm_cosigner_share (
  deal_id text NOT NULL, slot text NOT NULL, epoch integer NOT NULL, group_pub text NOT NULL,
  nonce bytea NOT NULL, ciphertext bytea NOT NULL, PRIMARY KEY (deal_id, slot)
);

-- Recoveries (DESIGN 6.4 recovery rules): one open recovery per slot.
CREATE TABLE recovery_agent_recovery (
  recovery_id text PRIMARY KEY,
  deal_id     text NOT NULL,
  slot        text NOT NULL,
  new_key_id  text NOT NULL,
  state       jsonb NOT NULL
);
CREATE UNIQUE INDEX recovery_agent_recovery_open ON recovery_agent_recovery (deal_id, slot)
  WHERE (state->>'status') IN ('pending', 'authorized');
CREATE TABLE recovery_agent_refresh (
  deal_id text NOT NULL, slot text NOT NULL, epoch integer NOT NULL, status text NOT NULL, missing jsonb NOT NULL,
  old_epoch_retired boolean NOT NULL, PRIMARY KEY (deal_id, slot, epoch)
);

-- The firm co-signer's WebAuthn credentials, used approvals and hash-chained audit log (task 3.10).
CREATE TABLE firm_cosigner_credential (
  deal_id text NOT NULL, slot text NOT NULL, credential_id text NOT NULL, public_key bytea NOT NULL,
  counter bigint NOT NULL DEFAULT 0, PRIMARY KEY (deal_id, slot, credential_id)
);
CREATE TABLE firm_cosigner_approval_use (approval_id text PRIMARY KEY);
CREATE TABLE firm_cosigner_audit (
  seq bigserial PRIMARY KEY, deal_id text NOT NULL, slot text NOT NULL, decision text NOT NULL, reason text NOT NULL,
  message_hash text NOT NULL, seal text NOT NULL, detail text NOT NULL, prev_hash text NOT NULL, entry_hash text NOT NULL
);
SELECT legx_make_append_only('firm_cosigner_audit');
SELECT legx_make_append_only('firm_cosigner_approval_use');

GRANT SELECT, INSERT, UPDATE ON presence_request TO app_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON frost_relay_session, frost_relay_message, recovery_agent_share,
  firm_cosigner_share, recovery_agent_recovery, recovery_agent_refresh, firm_cosigner_credential TO app_rw;
GRANT SELECT, INSERT ON firm_cosigner_approval_use, firm_cosigner_audit TO app_rw;
GRANT USAGE ON SEQUENCE firm_cosigner_audit_seq_seq TO app_rw;
