-- Purpose-bound money policies (JSON). expires_at is copied out so expiry sweeps can filter on it.
CREATE TABLE policies (
    policy_id TEXT PRIMARY KEY,
    expires_at BIGINT,
    doc TEXT NOT NULL
);

CREATE TABLE merchants (
    merchant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mcc INTEGER NOT NULL,
    mcc_label TEXT NOT NULL,
    region TEXT NOT NULL,
    verified INTEGER NOT NULL,
    balance_paise BIGINT NOT NULL
);

-- A UTXO leaves UNSPENT once: every spend and sweep is UPDATE ... WHERE status = 'UNSPENT'.
CREATE TABLE utxos (
    utxo_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    amount_paise BIGINT NOT NULL,
    policy_id TEXT NOT NULL,
    sponsor_id TEXT NOT NULL,
    status TEXT NOT NULL,
    unwrapped_from_policy TEXT,
    created_at BIGINT NOT NULL
);
CREATE INDEX utxos_status ON utxos (status);

-- Every transfer attempt, approved or not, as JSON with the policy VM's trace.
CREATE TABLE transfers (
    seq BIGINT PRIMARY KEY,
    tx_id TEXT NOT NULL UNIQUE,
    approved INTEGER NOT NULL,
    doc TEXT NOT NULL
);

CREATE TABLE sweeps (
    utxo_id TEXT PRIMARY KEY,
    swept_at BIGINT NOT NULL,
    doc TEXT NOT NULL
);

-- Simulated wallets. The ledger plays each wallet's secure element, so it keeps the secret s,
-- sealed: base64 of nonce + AES-256-GCM ciphertext. Points and recovered secrets are hex.
CREATE TABLE offline_wallets (
    wallet_id TEXT PRIMARY KEY,
    owner_name TEXT NOT NULL,
    sealed_secret TEXT NOT NULL,
    commitment_s TEXT NOT NULL UNIQUE,
    collateral_paise BIGINT NOT NULL,
    monotonic_counter BIGINT NOT NULL,
    slashed INTEGER NOT NULL,
    slashed_paise BIGINT NOT NULL,
    recovered_secret_s TEXT
);

-- Issued offline coins: the ledger's issuance record, plus the wallet side's sealed blinding r
-- and secure-element spend counter.
CREATE TABLE offline_coins (
    coin_id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL,
    counter BIGINT NOT NULL,
    amount_paise BIGINT NOT NULL,
    sealed_blinding TEXT NOT NULL,
    commitment_s TEXT NOT NULL,
    commitment_r TEXT NOT NULL,
    issuer_signature TEXT NOT NULL,
    spent_count INTEGER NOT NULL,
    UNIQUE (wallet_id, counter)
);

-- Spend packets uploaded by merchant terminals: PENDING until a sync claims one, then
-- SETTLED, DUPLICATE, REJECTED or DOUBLE_SPEND.
CREATE TABLE offline_packets (
    seq BIGINT PRIMARY KEY,
    packet_id TEXT NOT NULL,
    coin_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    doc TEXT NOT NULL
);
CREATE INDEX offline_packets_status ON offline_packets (status, seq);

-- One row per coin ever paid out: the primary key stops a coin being paid twice.
CREATE TABLE settled_coins (
    coin_id TEXT PRIMARY KEY,
    packet_seq BIGINT NOT NULL
);

CREATE TABLE double_spend_alerts (
    seq BIGINT PRIMARY KEY,
    coin_id TEXT NOT NULL,
    wallet_id TEXT NOT NULL,
    doc TEXT NOT NULL
);
