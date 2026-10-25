-- Tables DESIGN 9 does not list (task 3.1): deal_head, used_nonce, frost_nonce_use, plus deal_id and seq on outbox.

-- The gap-free per-deal seq (DESIGN 8.1). Working state, not evidence: one small mutable row per deal, locked FOR UPDATE.
-- head_seq is -1 before the first event. No foreign key, like evidence_event.
CREATE TABLE deal_head (
  deal_id   uuid PRIMARY KEY,
  head_seq  bigint NOT NULL CHECK (head_seq >= -1),
  head_hash bytea NOT NULL CHECK (length(head_hash) = 32)
);
-- The head only ever moves forward by exactly one, and never disappears.
CREATE FUNCTION deal_head_step() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR NEW.deal_id <> OLD.deal_id OR NEW.head_seq <> OLD.head_seq + 1 THEN
    RAISE EXCEPTION 'deal_head moves forward by one';
  END IF;
  RETURN NEW;
END$$;
CREATE TRIGGER deal_head_step BEFORE UPDATE OR DELETE ON deal_head FOR EACH ROW EXECUTE FUNCTION deal_head_step();
CREATE TRIGGER deal_head_no_truncate BEFORE TRUNCATE ON deal_head FOR EACH STATEMENT EXECUTE FUNCTION deny_mut();

-- Signed-request nonces (DESIGN 8.10). Rows older than 20 ledgers can be pruned, so the table is mutable.
CREATE TABLE used_nonce (
  nonce        bytea PRIMARY KEY CHECK (length(nonce) = 32),
  key_id       text NOT NULL,
  ledger_index bigint NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX used_nonce_ledger_idx ON used_nonce (ledger_index);

-- Server share holders mark a FROST nonce commitment used in one atomic insert, before they release a share (DESIGN 6.4).
-- Deleting a row would allow nonce reuse, so it is append-only.
CREATE TABLE frost_nonce_use (
  key_id        text NOT NULL,
  commitment_id text NOT NULL,
  deal_id       uuid NOT NULL,
  message_hash  bytea NOT NULL CHECK (length(message_hash) = 32),
  used_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (key_id, commitment_id)
);

ALTER TABLE outbox ADD COLUMN deal_id uuid, ADD COLUMN seq bigint,
  ADD CONSTRAINT outbox_deal_seq_both CHECK ((deal_id IS NULL) = (seq IS NULL));
CREATE INDEX outbox_deal_seq_idx ON outbox (deal_id, seq);
CREATE INDEX outbox_unsent_idx ON outbox (created_at, id) WHERE sent_at IS NULL;

-- Name the tables: a blanket GRANT here would give UPDATE on the append-only tables back.
GRANT SELECT, INSERT, UPDATE, DELETE ON deal_head, used_nonce TO app_rw;
GRANT SELECT, INSERT ON frost_nonce_use TO app_rw;
SELECT legx_make_append_only('frost_nonce_use');
