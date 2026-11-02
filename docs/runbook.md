# Runbook

How to deploy, configure and operate the ledger service. Commands assume the repository root.

## Deploy

```bash
docker build -t programmable-cbdc-compliance:1.0.0 .
python -m cbdcguard.ops keygen          # one API key per client, plus the issuer and wallet keys
docker run -d --name cbdcguard -p 8018:8018 -v cbdcguard-data:/data \
  -e CBDCGUARD_ACCEPT_UNREVIEWED_CRYPTO=yes \
  -e CBDCGUARD_KEYS_FILE=/run/secrets/cbdcguard-keys.json \
  -e CBDCGUARD_ISSUER_KEY=... -e CBDCGUARD_WALLET_KEY=... \
  programmable-cbdc-compliance:1.0.0
curl -fsS http://127.0.0.1:8018/readyz
```

The image runs in production mode as a non-root user and keeps its SQLite database in the `/data`
volume. A fresh database is seeded with the demo merchants, vouchers and wallets (there is no API
to register real ones). The service refuses to start, and logs why, when anything required is
missing. In production it also logs a warning that the offline scheme is unreviewed; that is
expected. Terminate TLS in front of it.

For more than one replica, use Postgres (`CBDCGUARD_DATABASE_URL=postgresql://user:pass@host/db`),
give every replica the same issuer and wallet keys, and put a shared rate limiter at the ingress.
The spend and settlement guards are in SQL, so replicas can't double-pay.

Without Docker: `pip install -r requirements.lock && pip install -e .`, then `cbdcguard serve`.

## Configure

| Variable | Required in production | Meaning |
|---|---|---|
| `CBDCGUARD_ENV` | — | `development` (default) or `production` |
| `CBDCGUARD_ACCEPT_UNREVIEWED_CRYPTO` | `yes` | acknowledges that the offline e-cash scheme has not been reviewed by a cryptographer; production refuses to start without it |
| `CBDCGUARD_API_KEYS` / `CBDCGUARD_KEYS_FILE` | yes | JSON `{"sha256:<hex>": {"user": "...", "role": "..."}}`. Roles: `issuer` (mint, sweep, sync, read), `payments` (spend, read), `auditor` (`/state`), `monitor` (`/metrics`), `admin` (all, plus `/reset` outside production and `/bench`) |
| `CBDCGUARD_ISSUER_KEY` | yes | base64 Ed25519 private key seed, exactly 32 bytes |
| `CBDCGUARD_WALLET_KEY` | yes | base64 AES-256-GCM key, exactly 32 bytes |
| `CBDCGUARD_ISSUER_KEY_PREVIOUS`, `CBDCGUARD_WALLET_KEY_PREVIOUS` | — | comma-separated older keys still accepted while rotating |
| `CBDCGUARD_DATABASE_URL` | yes | `sqlite:////data/cbdcguard.db` or `postgresql://...` (default in development: in memory) |
| `CBDCGUARD_HOST`, `CBDCGUARD_PORT` | — | default `127.0.0.1:8018`; any non-loopback address needs API keys |
| `CBDCGUARD_RATE_LIMIT` | — | requests per minute per client (default 120) |
| `CBDCGUARD_MAX_BODY_BYTES` | — | default 64,000 |
| `CBDCGUARD_CORS_ORIGINS` | — | comma-separated origins allowed to call from a browser; none by default |
| `CBDCGUARD_LOG_LEVEL` | — | default `INFO` |
| `FORWARDED_ALLOW_IPS` | — | addresses of proxies whose `X-Forwarded-For` is trusted (uvicorn) |

In development, missing keys are generated per process: coins issued and secrets sealed with them
are unusable after a restart. The service logs a warning when that happens.

## Watch

- `GET /healthz`: the process is up (used by the container health check).
- `GET /readyz`: database reachable; 503 otherwise.
- `GET /metrics` (role `monitor`): `http_requests_total`, `http_request_duration_seconds`,
  `errors_total`, `cbdcguard_decisions_total{decision="minted|approved|blocked|swept|offline_settled|offline_rejected|double_spend"}`.
- `GET /state` (role `auditor`): policies, merchants, the newest 500 UTXOs, the last 25 transfers,
  sweeps, wallets, pending packets, alerts and totals.
- Logs are one JSON object per line on stdout, each with a `request_id` that is also returned in the
  `X-Request-ID` response header.

Suggested alerts: `/readyz` failing for 2 minutes; `errors_total{kind="unhandled"}` increasing; 5xx
share above 1% for 10 minutes; any increase in `decision="double_spend"`; a rise in
`offline_rejected` (forged or unissued coins); `pending_offline_count` in `/state` growing (sync not
running).

## Rotate keys

**API keys.** Add the new hash to the key file, restart, give the client the new key, then remove
the old hash and restart again.

**Issuer key.** Set `CBDCGUARD_ISSUER_KEY_PREVIOUS` to the current key and `CBDCGUARD_ISSUER_KEY` to
a new one, then restart. New coins are signed with the new key; coins already issued still verify
and settle. Remove `_PREVIOUS` only once every coin signed with the old key has been spent and
synced, or those coins will be rejected.

**Wallet key.** Same pattern with `CBDCGUARD_WALLET_KEY_PREVIOUS`. Rows sealed with the old key stay
readable but are not re-sealed, so keep the old key in `_PREVIOUS` as long as those wallets and
coins exist.

## Back up and restore

SQLite (in the `/data` volume):

```bash
docker exec cbdcguard python -c "import sqlite3; s=sqlite3.connect('/data/cbdcguard.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
docker cp cbdcguard:/data/backup.db ./cbdcguard-$(date +%F).db
```

Restore: stop the container, copy the backup to `/data/cbdcguard.db` in the volume, start it, check
`/readyz` and the totals in `/state`. Packets synced after the backup was taken are lost: merchant
terminals must upload them again (duplicates are recognised).

Postgres: `pg_dump` / `pg_restore` as usual. Migrations are applied automatically on start, or with
`python -m cbdcguard migrate`.

Backups hold sealed wallet secrets: store them like the database, and keep the issuer and wallet
keys that were in use (including `_PREVIOUS`) with a separate custodian.

## Incidents

1. **Leaked API key.** Remove its hash from the key file and restart. Check transfers and mints made
   with it in the logs. Issue a new key.
2. **Leaked issuer key.** Rotate it *without* `_PREVIOUS` (old coins stop settling), restart, and
   reissue outstanding offline coins. Sync never pays coins missing from the ledger's own records,
   so forged coins are rejected, but terminals offline will accept them until they update.
3. **Leaked wallet key with the database.** Treat every simulated wallet as compromised: anyone can
   produce spends for it or frame it with a double spend. Rotate the key and re-register wallets.
4. **Double spend alert.** The alert names the wallet and shows the recovered s and that it matches
   S; collateral has been slashed. Block the wallet from further minting (slashed wallets already
   are) and recover the shortfall through the scheme's rules.
5. **Database unavailable.** `/readyz` returns 503 and writes fail with 500. Nothing is queued;
   callers and terminals retry.
