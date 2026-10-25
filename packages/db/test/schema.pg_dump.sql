--
-- PostgreSQL database dump
--



SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: deal_head_step(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.deal_head_step() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP <> 'UPDATE' OR NEW.deal_id <> OLD.deal_id OR NEW.head_seq <> OLD.head_seq + 1 THEN
    RAISE EXCEPTION 'deal_head moves forward by one';
  END IF;
  RETURN NEW;
END$$;


--
-- Name: deny_mut(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.deny_mut() RETURNS trigger
    LANGUAGE plpgsql
    AS $$BEGIN RAISE EXCEPTION 'append-only'; END$$;


--
-- Name: legx_make_append_only(regclass); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.legx_make_append_only(t regclass) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
  EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %s FROM app_rw', t);
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION deny_mut()',
                 replace(t::text, '"', '') || '_immutable', t);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION deny_mut()',
                 replace(t::text, '"', '') || '_no_truncate', t);
END $$;


--
-- Name: outbox_notify(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.outbox_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN PERFORM pg_notify('legx_outbox', COALESCE(NEW.deal_id::text, NEW.topic)); RETURN NEW; END $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: attorney_credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attorney_credential (
    ops_account text NOT NULL,
    verification_sha256 bytea NOT NULL,
    create_tx_hash text NOT NULL,
    accept_tx_hash text,
    expiration bigint NOT NULL
);


--
-- Name: bar_deal_link; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bar_deal_link (
    deal_id uuid NOT NULL,
    role text NOT NULL,
    envelope bytea NOT NULL,
    verification_sha256 bytea NOT NULL,
    CONSTRAINT bar_deal_link_role_check CHECK ((role = ANY (ARRAY['lawyerA'::text, 'lawyerB'::text])))
);


--
-- Name: bar_verification; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bar_verification (
    envelope_sha256 bytea NOT NULL,
    ops_account text NOT NULL,
    envelope bytea NOT NULL,
    status text NOT NULL,
    checked_at_ledger bigint NOT NULL,
    checked_at_ledger_hash text NOT NULL,
    CONSTRAINT bar_verification_envelope_sha256_check CHECK ((length(envelope_sha256) = 32)),
    CONSTRAINT bar_verification_status_check CHECK ((status = ANY (ARRAY['active'::text, 'not_active'::text])))
);


--
-- Name: checkpoint_anchor; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.checkpoint_anchor (
    tree_size bigint NOT NULL,
    root bytea NOT NULL,
    checkpoint bytea NOT NULL,
    anchor_tx_hash text,
    anchor_ledger bigint,
    rfc3161_token bytea,
    CONSTRAINT checkpoint_anchor_root_check CHECK ((length(root) = 32))
);


--
-- Name: deal; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.deal (
    deal_id uuid DEFAULT uuidv7() NOT NULL,
    state text NOT NULL,
    was_locked boolean DEFAULT false NOT NULL,
    network text NOT NULL,
    contract_root bytea NOT NULL,
    deal_seal bytea,
    shell_address text,
    signed_contract_seal bytea,
    nft_token_id text,
    mint_tx_hash text,
    lawyer_ops_a text,
    lawyer_ops_b text,
    escrow_owner text,
    escrow_sequence bigint,
    condition_hex text,
    cancel_after bigint,
    exit_slot bigint,
    payout_a text NOT NULL,
    payout_b text NOT NULL,
    releaser_account text,
    amount_drops numeric(20,0) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT deal_amount_drops_check CHECK ((amount_drops >= (0)::numeric)),
    CONSTRAINT deal_contract_root_check CHECK ((length(contract_root) = 32)),
    CONSTRAINT deal_deal_seal_check CHECK ((length(deal_seal) = 32)),
    CONSTRAINT deal_network_check CHECK ((network = ANY (ARRAY['standalone'::text, 'testnet'::text, 'devnet'::text, 'mainnet'::text]))),
    CONSTRAINT deal_releaser_is_ops_b CHECK (((releaser_account IS NULL) OR (NOT (releaser_account IS DISTINCT FROM lawyer_ops_b)))),
    CONSTRAINT deal_signed_contract_seal_check CHECK ((length(signed_contract_seal) = 32)),
    CONSTRAINT deal_state_check CHECK ((state = ANY (ARRAY['DRAFT'::text, 'CONTRACT_SIGNED'::text, 'SHELL_OPEN'::text, 'QUARANTINED'::text, 'KEYS_READY'::text, 'WALLET_LOCKED'::text, 'VERIFIED'::text, 'FUNDED'::text, 'PAID_OUT'::text, 'REFUNDED'::text, 'DISPUTED'::text, 'EXPIRED'::text, 'CLOSED'::text])))
);


--
-- Name: deal_head; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.deal_head (
    deal_id uuid NOT NULL,
    head_seq bigint NOT NULL,
    head_hash bytea NOT NULL,
    CONSTRAINT deal_head_head_hash_check CHECK ((length(head_hash) = 32)),
    CONSTRAINT deal_head_head_seq_check CHECK ((head_seq >= '-1'::integer))
);


--
-- Name: deal_key; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.deal_key (
    deal_id uuid NOT NULL,
    role text NOT NULL,
    xrpl_pubkey text NOT NULL,
    xrpl_account text NOT NULL,
    commitment bytea NOT NULL,
    binding_sig bytea NOT NULL,
    slot_policy bytea NOT NULL,
    pq_key_hash bytea NOT NULL,
    pq_binding_sigs jsonb NOT NULL,
    pq_cross_sig bytea NOT NULL,
    id_method text,
    contract_sig bytea,
    ops_account text,
    ops_bind_sig_ops bytea,
    ops_bind_sig_lawyer bytea,
    CONSTRAINT deal_key_binding_sig_check CHECK ((length(binding_sig) = 64)),
    CONSTRAINT deal_key_commitment_check CHECK ((length(commitment) = 32)),
    CONSTRAINT deal_key_contract_sig_check CHECK ((length(contract_sig) = 64)),
    CONSTRAINT deal_key_id_method CHECK ((id_method = ANY (ARRAY['zkpassport'::text, 'nfc-chip'::text]))),
    CONSTRAINT deal_key_id_method_clients_only CHECK (((role = ANY (ARRAY['alice'::text, 'bob'::text])) = (id_method IS NOT NULL))),
    CONSTRAINT deal_key_lawyer_fields CHECK (((role = ANY (ARRAY['lawyerA'::text, 'lawyerB'::text])) = ((contract_sig IS NOT NULL) AND (ops_account IS NOT NULL) AND (ops_bind_sig_ops IS NOT NULL) AND (ops_bind_sig_lawyer IS NOT NULL)))),
    CONSTRAINT deal_key_ops_bind_sig_lawyer_check CHECK ((length(ops_bind_sig_lawyer) = 64)),
    CONSTRAINT deal_key_ops_bind_sig_ops_check CHECK (((length(ops_bind_sig_ops) >= 64) AND (length(ops_bind_sig_ops) <= 72))),
    CONSTRAINT deal_key_pq_binding_sigs_two CHECK (((jsonb_typeof(pq_binding_sigs) = 'array'::text) AND (jsonb_array_length(pq_binding_sigs) = 2) AND ((pq_binding_sigs -> 0) ?& ARRAY['key_id'::text, 'sig'::text]) AND ((pq_binding_sigs -> 1) ?& ARRAY['key_id'::text, 'sig'::text]))),
    CONSTRAINT deal_key_pq_cross_sig_check CHECK ((length(pq_cross_sig) = 64)),
    CONSTRAINT deal_key_pq_key_hash_32 CHECK ((length(pq_key_hash) = 32)),
    CONSTRAINT deal_key_role_check CHECK ((role = ANY (ARRAY['alice'::text, 'lawyerA'::text, 'bob'::text, 'lawyerB'::text]))),
    CONSTRAINT deal_key_slot_policy_check CHECK ((length(slot_policy) = 32)),
    CONSTRAINT deal_key_xrpl_pubkey_check CHECK ((xrpl_pubkey ~ '^ED[0-9A-F]{64}$'::text))
);


--
-- Name: enrollment_key; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrollment_key (
    key_id text NOT NULL,
    deal_id uuid NOT NULL,
    slot text NOT NULL,
    holder_role text NOT NULL,
    ed25519_pub bytea NOT NULL,
    mldsa65_pub bytea NOT NULL,
    valid_from bigint NOT NULL,
    valid_to bigint,
    evidence_event_id uuid NOT NULL,
    CONSTRAINT enrollment_key_ed25519_pub_check CHECK ((length(ed25519_pub) = 32)),
    CONSTRAINT enrollment_key_holder_role_check CHECK ((holder_role = ANY (ARRAY['phone'::text, 'second-authenticator'::text, 'passkey-same-device'::text, 'recovery-agent'::text, 'console'::text, 'firm-hsm'::text, 'partner'::text]))),
    CONSTRAINT enrollment_key_mldsa65_pub_check CHECK ((length(mldsa65_pub) = 1952)),
    CONSTRAINT enrollment_key_slot_check CHECK ((slot = ANY (ARRAY['A'::text, 'LA'::text, 'B'::text, 'LB'::text])))
);


--
-- Name: evidence_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence_event (
    event_id uuid DEFAULT uuidv7() NOT NULL,
    deal_id uuid NOT NULL,
    seq bigint NOT NULL,
    prev_hash bytea NOT NULL,
    envelope bytea NOT NULL,
    leaf_hash bytea NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT evidence_event_envelope_check CHECK ((length(envelope) > 0)),
    CONSTRAINT evidence_event_leaf_hash_check CHECK ((length(leaf_hash) = 32)),
    CONSTRAINT evidence_event_prev_hash_check CHECK ((length(prev_hash) = 32)),
    CONSTRAINT evidence_event_seq_check CHECK ((seq >= 0))
);


--
-- Name: evidence_log_entry; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.evidence_log_entry (
    event_id uuid NOT NULL,
    log_index bigint NOT NULL,
    CONSTRAINT evidence_log_entry_log_index_check CHECK ((log_index >= 0))
);


--
-- Name: firm_cosigner_approval_use; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.firm_cosigner_approval_use (
    approval_id text NOT NULL
);


--
-- Name: firm_cosigner_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.firm_cosigner_audit (
    seq bigint NOT NULL,
    deal_id text NOT NULL,
    slot text NOT NULL,
    decision text NOT NULL,
    reason text NOT NULL,
    message_hash text NOT NULL,
    seal text NOT NULL,
    detail text NOT NULL,
    prev_hash text NOT NULL,
    entry_hash text NOT NULL
);


--
-- Name: firm_cosigner_audit_seq_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.firm_cosigner_audit_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: firm_cosigner_audit_seq_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.firm_cosigner_audit_seq_seq OWNED BY public.firm_cosigner_audit.seq;


--
-- Name: firm_cosigner_credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.firm_cosigner_credential (
    deal_id text NOT NULL,
    slot text NOT NULL,
    credential_id text NOT NULL,
    public_key bytea NOT NULL,
    counter bigint DEFAULT 0 NOT NULL
);


--
-- Name: firm_cosigner_share; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.firm_cosigner_share (
    deal_id text NOT NULL,
    slot text NOT NULL,
    epoch integer NOT NULL,
    group_pub text NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL
);


--
-- Name: frost_nonce_use; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.frost_nonce_use (
    key_id text NOT NULL,
    commitment_id text NOT NULL,
    deal_id uuid NOT NULL,
    message_hash bytea NOT NULL,
    used_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT frost_nonce_use_message_hash_check CHECK ((length(message_hash) = 32))
);


--
-- Name: frost_relay_message; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.frost_relay_message (
    session_id text NOT NULL,
    seq integer NOT NULL,
    kind text NOT NULL,
    from_id text NOT NULL,
    to_id text NOT NULL,
    signed jsonb NOT NULL
);


--
-- Name: frost_relay_session; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.frost_relay_session (
    session_id text NOT NULL,
    deal_id text NOT NULL,
    slot text NOT NULL,
    purpose text NOT NULL,
    participants jsonb NOT NULL,
    status text NOT NULL,
    attempt integer NOT NULL,
    parent text,
    pair jsonb,
    deadline_ms bigint,
    next_seq integer DEFAULT 0 NOT NULL
);


--
-- Name: identity_box; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_box (
    deal_id uuid NOT NULL,
    side text NOT NULL,
    kind text NOT NULL,
    box jsonb NOT NULL,
    CONSTRAINT identity_box_box_check CHECK ((jsonb_typeof(box) = 'object'::text)),
    CONSTRAINT identity_box_kind_check CHECK ((kind = ANY (ARRAY['zk-salt'::text, 'zk-disclosure'::text]))),
    CONSTRAINT identity_box_side_check CHECK ((side = ANY (ARRAY['A'::text, 'B'::text])))
);


--
-- Name: kysely_migration; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kysely_migration (
    name character varying(255) NOT NULL,
    "timestamp" character varying(255) NOT NULL
);


--
-- Name: kysely_migration_lock; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kysely_migration_lock (
    id character varying(255) NOT NULL,
    is_locked integer DEFAULT 0 NOT NULL
);


--
-- Name: lawyer; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lawyer (
    ops_account text NOT NULL,
    jurisdiction text NOT NULL,
    bar_number_sha256 bytea NOT NULL,
    CONSTRAINT lawyer_bar_number_sha256_check CHECK ((length(bar_number_sha256) = 32))
);


--
-- Name: ledger_observation; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ledger_observation (
    tx_hash bytea NOT NULL,
    ledger_index bigint NOT NULL,
    tx_index integer NOT NULL,
    account text NOT NULL,
    tx_type text NOT NULL,
    result text NOT NULL,
    meta jsonb NOT NULL,
    CONSTRAINT ledger_observation_tx_hash_check CHECK ((length(tx_hash) = 32))
);


--
-- Name: outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.outbox (
    id uuid DEFAULT uuidv7() NOT NULL,
    topic text NOT NULL,
    payload bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    deal_id uuid,
    seq bigint,
    CONSTRAINT outbox_deal_seq_both CHECK (((deal_id IS NULL) = (seq IS NULL)))
);


--
-- Name: passport_attestation; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.passport_attestation (
    deal_id uuid NOT NULL,
    side text NOT NULL,
    envelope bytea NOT NULL,
    anchor_ledger bigint NOT NULL,
    leaf_hash bytea NOT NULL,
    CONSTRAINT passport_attestation_leaf_hash_check CHECK ((length(leaf_hash) = 32)),
    CONSTRAINT passport_attestation_side_check CHECK ((side = ANY (ARRAY['A'::text, 'B'::text])))
);


--
-- Name: presence_request; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.presence_request (
    deal_id uuid NOT NULL,
    side text NOT NULL,
    method text NOT NULL,
    lawyer_nonce text NOT NULL,
    ledger_hash text NOT NULL,
    ledger_index bigint NOT NULL,
    signature text,
    CONSTRAINT presence_request_lawyer_nonce_check CHECK ((lawyer_nonce ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT presence_request_ledger_hash_check CHECK ((ledger_hash ~ '^[0-9A-F]{64}$'::text)),
    CONSTRAINT presence_request_method_check CHECK ((method = ANY (ARRAY['zkpassport'::text, 'nfc-chip'::text]))),
    CONSTRAINT presence_request_side_check CHECK ((side = ANY (ARRAY['A'::text, 'B'::text]))),
    CONSTRAINT presence_request_signature_check CHECK ((signature ~ '^[0-9a-f]{128}$'::text))
);


--
-- Name: recovery_agent_recovery; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.recovery_agent_recovery (
    recovery_id text NOT NULL,
    deal_id text NOT NULL,
    slot text NOT NULL,
    new_key_id text NOT NULL,
    state jsonb NOT NULL
);


--
-- Name: recovery_agent_refresh; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.recovery_agent_refresh (
    deal_id text NOT NULL,
    slot text NOT NULL,
    epoch integer NOT NULL,
    status text NOT NULL,
    missing jsonb NOT NULL,
    old_epoch_retired boolean NOT NULL
);


--
-- Name: recovery_agent_share; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.recovery_agent_share (
    deal_id text NOT NULL,
    slot text NOT NULL,
    epoch integer NOT NULL,
    group_pub text NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL
);


--
-- Name: release_gate; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.release_gate (
    deal_id uuid NOT NULL,
    leaf_hash bytea NOT NULL,
    envelope bytea NOT NULL,
    ledger_index bigint NOT NULL,
    CONSTRAINT release_gate_leaf_hash_check CHECK ((length(leaf_hash) = 32))
);


--
-- Name: signature; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.signature (
    request_id uuid NOT NULL,
    role text NOT NULL,
    signer_blob text NOT NULL
);


--
-- Name: signature_request; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.signature_request (
    request_id uuid DEFAULT uuidv7() NOT NULL,
    deal_id uuid NOT NULL,
    purpose text NOT NULL,
    unsigned_tx jsonb NOT NULL,
    last_ledger bigint NOT NULL,
    status text DEFAULT 'open'::text NOT NULL
);


--
-- Name: used_nonce; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.used_nonce (
    nonce bytea NOT NULL,
    key_id text NOT NULL,
    ledger_index bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT used_nonce_nonce_check CHECK ((length(nonce) = 32))
);


--
-- Name: watcher_cursor; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.watcher_cursor (
    account text NOT NULL,
    last_validated_ledger bigint NOT NULL
);


--
-- Name: zk_proof; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.zk_proof (
    deal_id uuid NOT NULL,
    side text NOT NULL,
    stage text NOT NULL,
    proof bytea NOT NULL,
    registry_roots jsonb NOT NULL,
    identifier_hash bytea NOT NULL,
    CONSTRAINT zk_proof_identifier_hash_check CHECK ((length(identifier_hash) = 32)),
    CONSTRAINT zk_proof_registry_roots_check CHECK ((jsonb_typeof(registry_roots) = 'object'::text)),
    CONSTRAINT zk_proof_side_check CHECK ((side = ANY (ARRAY['A'::text, 'B'::text]))),
    CONSTRAINT zk_proof_stage_check CHECK ((stage = ANY (ARRAY['onboarding'::text, 'release'::text])))
);


--
-- Name: firm_cosigner_audit seq; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.firm_cosigner_audit ALTER COLUMN seq SET DEFAULT nextval('public.firm_cosigner_audit_seq_seq'::regclass);


--
-- Name: attorney_credential attorney_credential_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attorney_credential
    ADD CONSTRAINT attorney_credential_pkey PRIMARY KEY (ops_account, create_tx_hash);


--
-- Name: bar_deal_link bar_deal_link_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bar_deal_link
    ADD CONSTRAINT bar_deal_link_pkey PRIMARY KEY (deal_id, role, verification_sha256);


--
-- Name: bar_verification bar_verification_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bar_verification
    ADD CONSTRAINT bar_verification_pkey PRIMARY KEY (envelope_sha256);


--
-- Name: checkpoint_anchor checkpoint_anchor_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.checkpoint_anchor
    ADD CONSTRAINT checkpoint_anchor_pkey PRIMARY KEY (tree_size);


--
-- Name: deal_head deal_head_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deal_head
    ADD CONSTRAINT deal_head_pkey PRIMARY KEY (deal_id);


--
-- Name: deal_key deal_key_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deal_key
    ADD CONSTRAINT deal_key_pkey PRIMARY KEY (deal_id, role);


--
-- Name: deal deal_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deal
    ADD CONSTRAINT deal_pkey PRIMARY KEY (deal_id);


--
-- Name: enrollment_key enrollment_key_holder_keys_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrollment_key
    ADD CONSTRAINT enrollment_key_holder_keys_key UNIQUE (deal_id, slot, holder_role, ed25519_pub, mldsa65_pub);


--
-- Name: enrollment_key enrollment_key_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrollment_key
    ADD CONSTRAINT enrollment_key_pkey PRIMARY KEY (key_id);


--
-- Name: evidence_event evidence_event_deal_id_seq_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_event
    ADD CONSTRAINT evidence_event_deal_id_seq_key UNIQUE (deal_id, seq);


--
-- Name: evidence_event evidence_event_leaf_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_event
    ADD CONSTRAINT evidence_event_leaf_hash_key UNIQUE (leaf_hash);


--
-- Name: evidence_event evidence_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_event
    ADD CONSTRAINT evidence_event_pkey PRIMARY KEY (event_id);


--
-- Name: evidence_log_entry evidence_log_entry_log_index_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_log_entry
    ADD CONSTRAINT evidence_log_entry_log_index_key UNIQUE (log_index);


--
-- Name: evidence_log_entry evidence_log_entry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_log_entry
    ADD CONSTRAINT evidence_log_entry_pkey PRIMARY KEY (event_id);


--
-- Name: firm_cosigner_approval_use firm_cosigner_approval_use_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.firm_cosigner_approval_use
    ADD CONSTRAINT firm_cosigner_approval_use_pkey PRIMARY KEY (approval_id);


--
-- Name: firm_cosigner_audit firm_cosigner_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.firm_cosigner_audit
    ADD CONSTRAINT firm_cosigner_audit_pkey PRIMARY KEY (seq);


--
-- Name: firm_cosigner_credential firm_cosigner_credential_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.firm_cosigner_credential
    ADD CONSTRAINT firm_cosigner_credential_pkey PRIMARY KEY (deal_id, slot, credential_id);


--
-- Name: firm_cosigner_share firm_cosigner_share_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.firm_cosigner_share
    ADD CONSTRAINT firm_cosigner_share_pkey PRIMARY KEY (deal_id, slot);


--
-- Name: frost_nonce_use frost_nonce_use_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.frost_nonce_use
    ADD CONSTRAINT frost_nonce_use_pkey PRIMARY KEY (key_id, commitment_id);


--
-- Name: frost_relay_message frost_relay_message_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.frost_relay_message
    ADD CONSTRAINT frost_relay_message_pkey PRIMARY KEY (session_id, seq);


--
-- Name: frost_relay_message frost_relay_message_session_id_kind_from_id_to_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.frost_relay_message
    ADD CONSTRAINT frost_relay_message_session_id_kind_from_id_to_id_key UNIQUE (session_id, kind, from_id, to_id);


--
-- Name: frost_relay_session frost_relay_session_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.frost_relay_session
    ADD CONSTRAINT frost_relay_session_pkey PRIMARY KEY (session_id);


--
-- Name: identity_box identity_box_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_box
    ADD CONSTRAINT identity_box_pkey PRIMARY KEY (deal_id, side, kind);


--
-- Name: kysely_migration_lock kysely_migration_lock_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kysely_migration_lock
    ADD CONSTRAINT kysely_migration_lock_pkey PRIMARY KEY (id);


--
-- Name: kysely_migration kysely_migration_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kysely_migration
    ADD CONSTRAINT kysely_migration_pkey PRIMARY KEY (name);


--
-- Name: lawyer lawyer_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lawyer
    ADD CONSTRAINT lawyer_pkey PRIMARY KEY (ops_account);


--
-- Name: ledger_observation ledger_observation_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ledger_observation
    ADD CONSTRAINT ledger_observation_pkey PRIMARY KEY (tx_hash);


--
-- Name: outbox outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.outbox
    ADD CONSTRAINT outbox_pkey PRIMARY KEY (id);


--
-- Name: passport_attestation passport_attestation_leaf_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.passport_attestation
    ADD CONSTRAINT passport_attestation_leaf_hash_key UNIQUE (leaf_hash);


--
-- Name: passport_attestation passport_attestation_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.passport_attestation
    ADD CONSTRAINT passport_attestation_pkey PRIMARY KEY (deal_id, side, leaf_hash);


--
-- Name: presence_request presence_request_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.presence_request
    ADD CONSTRAINT presence_request_pkey PRIMARY KEY (deal_id, side);


--
-- Name: recovery_agent_recovery recovery_agent_recovery_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recovery_agent_recovery
    ADD CONSTRAINT recovery_agent_recovery_pkey PRIMARY KEY (recovery_id);


--
-- Name: recovery_agent_refresh recovery_agent_refresh_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recovery_agent_refresh
    ADD CONSTRAINT recovery_agent_refresh_pkey PRIMARY KEY (deal_id, slot, epoch);


--
-- Name: recovery_agent_share recovery_agent_share_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recovery_agent_share
    ADD CONSTRAINT recovery_agent_share_pkey PRIMARY KEY (deal_id, slot);


--
-- Name: release_gate release_gate_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.release_gate
    ADD CONSTRAINT release_gate_pkey PRIMARY KEY (leaf_hash);


--
-- Name: signature signature_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signature
    ADD CONSTRAINT signature_pkey PRIMARY KEY (request_id, role);


--
-- Name: signature_request signature_request_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signature_request
    ADD CONSTRAINT signature_request_pkey PRIMARY KEY (request_id);


--
-- Name: used_nonce used_nonce_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.used_nonce
    ADD CONSTRAINT used_nonce_pkey PRIMARY KEY (nonce);


--
-- Name: watcher_cursor watcher_cursor_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.watcher_cursor
    ADD CONSTRAINT watcher_cursor_pkey PRIMARY KEY (account);


--
-- Name: zk_proof zk_proof_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zk_proof
    ADD CONSTRAINT zk_proof_pkey PRIMARY KEY (deal_id, side, stage, identifier_hash);


--
-- Name: enrollment_key_holder_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX enrollment_key_holder_idx ON public.enrollment_key USING btree (deal_id, slot, holder_role);


--
-- Name: outbox_deal_seq_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX outbox_deal_seq_idx ON public.outbox USING btree (deal_id, seq);


--
-- Name: outbox_unsent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX outbox_unsent_idx ON public.outbox USING btree (created_at, id) WHERE (sent_at IS NULL);


--
-- Name: recovery_agent_recovery_open; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX recovery_agent_recovery_open ON public.recovery_agent_recovery USING btree (deal_id, slot) WHERE ((state ->> 'status'::text) = ANY (ARRAY['pending'::text, 'authorized'::text]));


--
-- Name: used_nonce_ledger_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX used_nonce_ledger_idx ON public.used_nonce USING btree (ledger_index);


--
-- Name: attorney_credential attorney_credential_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER attorney_credential_immutable BEFORE DELETE OR UPDATE ON public.attorney_credential FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: attorney_credential attorney_credential_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER attorney_credential_no_truncate BEFORE TRUNCATE ON public.attorney_credential FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: bar_deal_link bar_deal_link_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER bar_deal_link_immutable BEFORE DELETE OR UPDATE ON public.bar_deal_link FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: bar_deal_link bar_deal_link_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER bar_deal_link_no_truncate BEFORE TRUNCATE ON public.bar_deal_link FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: bar_verification bar_verification_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER bar_verification_immutable BEFORE DELETE OR UPDATE ON public.bar_verification FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: bar_verification bar_verification_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER bar_verification_no_truncate BEFORE TRUNCATE ON public.bar_verification FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: deal_head deal_head_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER deal_head_no_truncate BEFORE TRUNCATE ON public.deal_head FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: deal_head deal_head_step; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER deal_head_step BEFORE DELETE OR UPDATE ON public.deal_head FOR EACH ROW EXECUTE FUNCTION public.deal_head_step();


--
-- Name: enrollment_key enrollment_key_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enrollment_key_immutable BEFORE DELETE OR UPDATE ON public.enrollment_key FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: enrollment_key enrollment_key_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER enrollment_key_no_truncate BEFORE TRUNCATE ON public.enrollment_key FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: evidence_event evidence_event_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER evidence_event_immutable BEFORE DELETE OR UPDATE ON public.evidence_event FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: evidence_event evidence_event_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER evidence_event_no_truncate BEFORE TRUNCATE ON public.evidence_event FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: evidence_log_entry evidence_log_entry_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER evidence_log_entry_immutable BEFORE DELETE OR UPDATE ON public.evidence_log_entry FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: evidence_log_entry evidence_log_entry_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER evidence_log_entry_no_truncate BEFORE TRUNCATE ON public.evidence_log_entry FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: firm_cosigner_approval_use firm_cosigner_approval_use_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER firm_cosigner_approval_use_immutable BEFORE DELETE OR UPDATE ON public.firm_cosigner_approval_use FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: firm_cosigner_approval_use firm_cosigner_approval_use_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER firm_cosigner_approval_use_no_truncate BEFORE TRUNCATE ON public.firm_cosigner_approval_use FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: firm_cosigner_audit firm_cosigner_audit_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER firm_cosigner_audit_immutable BEFORE DELETE OR UPDATE ON public.firm_cosigner_audit FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: firm_cosigner_audit firm_cosigner_audit_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER firm_cosigner_audit_no_truncate BEFORE TRUNCATE ON public.firm_cosigner_audit FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: frost_nonce_use frost_nonce_use_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER frost_nonce_use_immutable BEFORE DELETE OR UPDATE ON public.frost_nonce_use FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: frost_nonce_use frost_nonce_use_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER frost_nonce_use_no_truncate BEFORE TRUNCATE ON public.frost_nonce_use FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: outbox outbox_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER outbox_notify AFTER INSERT ON public.outbox FOR EACH ROW EXECUTE FUNCTION public.outbox_notify();


--
-- Name: passport_attestation passport_attestation_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER passport_attestation_immutable BEFORE DELETE OR UPDATE ON public.passport_attestation FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: passport_attestation passport_attestation_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER passport_attestation_no_truncate BEFORE TRUNCATE ON public.passport_attestation FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: release_gate release_gate_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER release_gate_immutable BEFORE DELETE OR UPDATE ON public.release_gate FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: release_gate release_gate_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER release_gate_no_truncate BEFORE TRUNCATE ON public.release_gate FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: zk_proof zk_proof_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER zk_proof_immutable BEFORE DELETE OR UPDATE ON public.zk_proof FOR EACH ROW EXECUTE FUNCTION public.deny_mut();


--
-- Name: zk_proof zk_proof_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER zk_proof_no_truncate BEFORE TRUNCATE ON public.zk_proof FOR EACH STATEMENT EXECUTE FUNCTION public.deny_mut();


--
-- Name: attorney_credential attorney_credential_ops_account_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attorney_credential
    ADD CONSTRAINT attorney_credential_ops_account_fkey FOREIGN KEY (ops_account) REFERENCES public.lawyer(ops_account);


--
-- Name: attorney_credential attorney_credential_verification_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attorney_credential
    ADD CONSTRAINT attorney_credential_verification_sha256_fkey FOREIGN KEY (verification_sha256) REFERENCES public.bar_verification(envelope_sha256);


--
-- Name: bar_deal_link bar_deal_link_deal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bar_deal_link
    ADD CONSTRAINT bar_deal_link_deal_id_fkey FOREIGN KEY (deal_id) REFERENCES public.deal(deal_id);


--
-- Name: bar_deal_link bar_deal_link_verification_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bar_deal_link
    ADD CONSTRAINT bar_deal_link_verification_sha256_fkey FOREIGN KEY (verification_sha256) REFERENCES public.bar_verification(envelope_sha256);


--
-- Name: bar_verification bar_verification_ops_account_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bar_verification
    ADD CONSTRAINT bar_verification_ops_account_fkey FOREIGN KEY (ops_account) REFERENCES public.lawyer(ops_account);


--
-- Name: deal_key deal_key_deal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deal_key
    ADD CONSTRAINT deal_key_deal_id_fkey FOREIGN KEY (deal_id) REFERENCES public.deal(deal_id);


--
-- Name: enrollment_key enrollment_key_deal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrollment_key
    ADD CONSTRAINT enrollment_key_deal_id_fkey FOREIGN KEY (deal_id) REFERENCES public.deal(deal_id);


--
-- Name: enrollment_key enrollment_key_evidence_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrollment_key
    ADD CONSTRAINT enrollment_key_evidence_event_id_fkey FOREIGN KEY (evidence_event_id) REFERENCES public.evidence_event(event_id);


--
-- Name: evidence_log_entry evidence_log_entry_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.evidence_log_entry
    ADD CONSTRAINT evidence_log_entry_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.evidence_event(event_id);


--
-- Name: frost_relay_message frost_relay_message_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.frost_relay_message
    ADD CONSTRAINT frost_relay_message_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.frost_relay_session(session_id);


--
-- Name: identity_box identity_box_deal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_box
    ADD CONSTRAINT identity_box_deal_id_fkey FOREIGN KEY (deal_id) REFERENCES public.deal(deal_id);


--
-- Name: passport_attestation passport_attestation_deal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.passport_attestation
    ADD CONSTRAINT passport_attestation_deal_id_fkey FOREIGN KEY (deal_id) REFERENCES public.deal(deal_id);


--
-- Name: presence_request presence_request_deal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.presence_request
    ADD CONSTRAINT presence_request_deal_id_fkey FOREIGN KEY (deal_id) REFERENCES public.deal(deal_id);


--
-- Name: release_gate release_gate_deal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.release_gate
    ADD CONSTRAINT release_gate_deal_id_fkey FOREIGN KEY (deal_id) REFERENCES public.deal(deal_id);


--
-- Name: signature_request signature_request_deal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signature_request
    ADD CONSTRAINT signature_request_deal_id_fkey FOREIGN KEY (deal_id) REFERENCES public.deal(deal_id);


--
-- Name: signature signature_request_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signature
    ADD CONSTRAINT signature_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.signature_request(request_id);


--
-- Name: zk_proof zk_proof_deal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zk_proof
    ADD CONSTRAINT zk_proof_deal_id_fkey FOREIGN KEY (deal_id) REFERENCES public.deal(deal_id);


--
-- PostgreSQL database dump complete
--


