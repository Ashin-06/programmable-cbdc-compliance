# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## 1.0.0 — 2026-10-27

### Added
- `pyproject.toml` with a `cbdcguard` console command, and pinned `requirements.lock` /
  `requirements-dev.lock` (generated with `uv pip compile --universal`).
- Container image: slim Python 3.12 base, non-root user, health check on `/healthz`.
- CI on every push: ruff, bandit, pip-audit, pytest with a coverage report.
- Settings from `CBDCGUARD_*` environment variables, checked at startup. `CBDCGUARD_ENV=production`
  refuses to start without hashed API keys, `CBDCGUARD_ISSUER_KEY`, `CBDCGUARD_WALLET_KEY` and
  `CBDCGUARD_DATABASE_URL`. No built-in secrets in any mode.
- Roles on API keys: `issuer` mints, sweeps and syncs, `payments` spends, `auditor` reads the
  ledger, `monitor` scrapes metrics, `admin` does all of it plus reset and the benchmark. Keys can be
  stored as `sha256:<hex>`; `python -m cbdcguard.ops keygen` makes new ones.
- Per-client rate limit, request body cap (chunked bodies included), security headers, CORS only
  for listed origins.
- JSON logs with request IDs; `/healthz`, `/readyz` and Prometheus `/metrics`
  (`cbdcguard_decisions_total` counts approved, blocked and swept transfers, mints, and offline
  settlements, rejections and double spends).
- The ledger in a database: SQLite by default, Postgres through `CBDCGUARD_DATABASE_URL`,
  numbered SQL migrations (`python -m cbdcguard migrate`). A fresh database is seeded with the demo
  data.
- Key rotation: `CBDCGUARD_ISSUER_KEY_PREVIOUS` (coins signed by older issuer keys still verify) and
  `CBDCGUARD_WALLET_KEY_PREVIOUS` (older sealed secrets stay readable).
- A warning, logged at startup in production and returned by the `/offline/*` endpoints, that the
  offline scheme is unreviewed.
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`.

### Changed
- **Money is integer paise.** Requests take rupees as JSON numbers or decimal strings with at most
  two decimals (more decimals, NaN or infinity are refused); responses give rupees as strings
  (`"6000.10"`) next to `*_paise` integers. Python API: `mint_utxo(owner, amount_paise, ...)`,
  `transfer_utxo(..., amount_paise=...)`, `mint_offline_coin(wallet, amount_paise)`,
  `PBMPolicy.max_tx_paise`, `SpendContext.amount_paise`.
- **The ledger no longer lives in process memory.** Spends, sweeps, coin settlement and packet
  claims are guarded in SQL, so two replicas sharing a database can't spend a UTXO twice or pay a
  coin twice. `CBDCLedger` takes an engine and keys; `ledger.utxos[...]`-style dictionaries are
  replaced by `utxo()`, `merchant()`, `wallet()`, `alerts()` and `queue_packet()`.
- The issuer key comes from settings instead of being generated per process, and the simulated
  wallets' secrets s and blinding values r are sealed with AES-256-GCM in the database.
- `CBDCGUARD_API_KEY` (one shared key) is replaced by `CBDCGUARD_API_KEYS` with roles. Without keys
  the service refuses to listen on anything but loopback.
- `/health` is replaced by `/healthz` (liveness) and `/readyz` (database reachable). `/reset` needs
  the admin role and is refused in production. Validation errors no longer echo the submitted input.
- Registering a merchant or wallet ID twice is refused instead of silently replacing it.

### Unchanged
- Policy rules, the offline protocol and its checks. `python -m cbdcguard bench` was re-run on the
  database-backed ledger and gives the same results as before: 200/200 policy decisions as expected,
  75/75 unwraps, 25/25 sweeps, 25/25 double spends detected with s recovered, 0/75 honest wallets
  flagged.
