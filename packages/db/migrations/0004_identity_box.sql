-- OD-36 (b): the client's salt and ZK disclosure proof, sealed to its own lawyer (X-Wing boxes, DESIGN 6.2, 6.10).
-- The coordinator stores the box as received and never holds the plaintext; one box per (deal, side, kind), never replaced.
CREATE TABLE identity_box (
  deal_id uuid NOT NULL REFERENCES deal,
  side    text NOT NULL CHECK (side IN ('A', 'B')),
  kind    text NOT NULL CHECK (kind IN ('zk-salt', 'zk-disclosure')),
  box     jsonb NOT NULL CHECK (jsonb_typeof(box) = 'object'),
  PRIMARY KEY (deal_id, side, kind)
);
GRANT SELECT, INSERT ON identity_box TO app_rw;
