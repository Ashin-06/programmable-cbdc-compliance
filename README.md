# Programmable CBDC Compliance (`cbdcguard`)

A model of two ideas discussed for retail digital currencies such as the e-rupee:

1. **Purpose-bound money.** A subsidy or voucher token that can only be spent at certain kinds of merchants, in certain regions, up to a limit, before an expiry date. When a verified merchant receives it, it turns into ordinary money, and if it expires unspent it goes back to the sponsor.
2. **Offline payments with double-spend detection.** A wallet can pay a merchant terminal with no network. If someone clones the wallet and spends the same coin twice, the two payment records together reveal the wallet's secret key when the merchants later sync, which proves the double spend and identifies who did it.

Everything is a simulation. Policies, merchants and wallets are made up; the preset policies are generic examples, not RBI rules or the terms of any real scheme.

> **The offline scheme is a reference implementation.** Its group arithmetic is libsodium's Ed25519 (via PyNaCl) and its signatures use `cryptography`, but the protocol code is hand-written and has not been reviewed by a cryptographer. It is not a design anyone should issue currency with. In production mode the service logs a warning saying so, and the offline endpoints return it.

## How it works

**Policy VM** (`policy_vm.py`). A policy is compiled into a short list of stack-machine instructions:
- an expiry check;
- a minimum KYC tier;
- blocked merchant category codes (gambling 7995, ATM cash-out 6011);
- allowed merchant categories;
- an allowed set of regions;
- a per-transaction ceiling;
- a verified-merchant requirement;
- an unwrap flag.

Running it returns an allow/deny decision, the violation code, and an instruction trace. The ledger (`ledger.py`) spends UTXOs against these policies, creates change UTXOs that keep the original policy, unwraps on approved settlement, and sweeps expired UTXOs back to the sponsor. Reused UTXO, coin, policy, merchant and wallet IDs are rejected. Money is integer paise throughout.

**Offline coins** (`offline.py`).
- **Withdrawal.** A wallet has a secret s and public key S = s·G. For each coin it picks a random r, with R = r·G. The issuer signs the coin's ID, wallet, counter, amount, S and R with Ed25519.
- **Payment.** The terminal derives a challenge x from its merchant ID, the time, its nonce and the coin ID. The wallet answers y = s·x + r. The terminal checks the issuer signature and that y·G = x·S + R, with no network needed.
- **Sync.** The ledger pays only coins it actually issued, and pays the amount it recorded. A packet submitted twice is a duplicate and is paid once. Two different answers for one coin give s = (y₁ − y₂)/(x₁ − x₂); the ledger checks s against S and slashes the wallet's collateral.
- **What the hardware is assumed to do.** A counter in the wallet's secure element is supposed to stop it answering twice. The double-spend path is simulated by switching that guard off.

## Results

`python -m cbdcguard bench`:

| Check | Result |
|---|---|
| 200 policy decisions (75 allowed, plus 25 each of blocked category, wrong category, out of region, over limit, expired) | 200/200 as expected |
| allowed spends that unwrapped to general money | 75/75 |
| expired spend attempts swept to the sponsor | 25/25 |
| offline double spends detected, with s recovered and checked against S | 25/25 |
| honest offline wallets flagged or slashed | 0/75 |

These are consistency checks on hand-built cases, not measurements. The policy cases are generated to exercise each rule. Recovering s from two answers is algebra that always works when the challenges differ. That one answer reveals nothing about s follows from r being random and single-use; the benchmark doesn't (and can't) measure it.

## Run it

```bash
pip install -r requirements-dev.lock && pip install -e .
python -m pytest -q                      # 41 tests
python -m cbdcguard bench
python -m cbdcguard serve                # API + console at http://127.0.0.1:8018
```

Endpoints: `GET /state`, `POST /reset`, `POST /cbdc/mint`, `POST /cbdc/transfer`, `POST /cbdc/sweep`, `POST /offline/mint`, `POST /offline/spend`, `POST /offline/sync`, `GET /bench`, plus `GET /healthz`, `GET /readyz` and `GET /metrics`.

**Money.** Amounts in requests are rupees as JSON numbers or decimal strings with at most two decimals (`"6000.10"`); more decimals, NaN and infinity are refused. Responses give rupees as strings next to `*_paise` integers. Inside the ledger everything is integer paise.

**Settings and access.** The service reads `CBDCGUARD_*` environment variables (see `docs/runbook.md`). Callers send an API key in `X-API-Key` (the console has a field for it) or `Authorization: Bearer`. Each key has a role: `issuer` mints, sweeps and syncs; `payments` spends; `auditor` reads `/state`; `monitor` reads metrics; `admin` can do all of that plus `/reset` and `/bench`. `python -m cbdcguard.ops keygen` makes a key and the hash to configure, plus fresh issuer and wallet keys. Without keys the service runs open in development and refuses to listen on anything but loopback. `CBDCGUARD_ENV=production` refuses to start without hashed keys, `CBDCGUARD_ISSUER_KEY` (the Ed25519 seed coins are signed with), `CBDCGUARD_WALLET_KEY` (seals the simulated wallets' secrets) and a database, and refuses `/reset`.

**State.** The ledger is kept in SQLite or Postgres (`CBDCGUARD_DATABASE_URL`); a fresh database is seeded with the demo data. Spends, sweeps, coin settlement and packet claims are guarded in SQL, so replicas sharing a database can't spend a UTXO or pay a coin twice. Because the service also plays the wallets' secure elements, it stores each wallet's s and each coin's r, sealed with AES-256-GCM.

**Docker.**

```bash
docker build -t programmable-cbdc-compliance:1.0.0 .
docker run -d -p 8018:8018 -v cbdcguard-data:/data -e CBDCGUARD_API_KEYS='{"sha256:...": {"user": "ops", "role": "admin"}}'   -e CBDCGUARD_ISSUER_KEY=... -e CBDCGUARD_WALLET_KEY=... programmable-cbdc-compliance:1.0.0
```

The image runs in production mode as a non-root user. Run without keys it exits with a configuration error.

## Limits

- **Simulation only.** No connection to any real CBDC system, and the service plays the wallets and terminals itself, so it holds secrets (sealed) that a real ledger would never see. There is no API to register real merchants or wallets.
- **The API trusts its caller within a role.** There are no user accounts or signatures on spends: a `payments` key can spend any UTXO and state the sender's KYC tier, and an `issuer` key can mint any amount. A real ledger would require the owner's signature on every spend and take KYC from its own records.
- **Offline payments are not private from merchants or the ledger.** Every coin carries the wallet ID and the same public key S, so all of a wallet's payments are linkable. Unlinkable offline cash needs blind signatures or anonymous credentials (Chaum, Brands), which this doesn't do. The only privacy property is that one payment doesn't reveal s.
- **Double-spend detection is after the fact.** The second merchant has already accepted the coin, and recovery depends on slashing collateral the wallet may not have. Real offline schemes also cap offline balances and how long a wallet may stay offline.
- **Unreviewed cryptographic protocol.** See the note at the top.

## Production readiness

In place (1.0.0):
- Settings checked at startup; production refuses to start without hashed API keys, the issuer and wallet keys and a database, and never listens publicly without keys.
- API keys with roles, per-client rate limit, request body cap, security headers, CORS only for listed origins, validation errors that don't echo input.
- The ledger in a database with migrations, integer paise, and spend guards in SQL that hold across replicas.
- Issuer key from settings with rotation; simulated wallet secrets sealed at rest, with rotation.
- JSON logs with request IDs, `/healthz`, `/readyz`, Prometheus `/metrics`.
- Pinned dependency locks, a non-root container image with a health check, CI running ruff, bandit, pip-audit and the tests.
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`.

Still needed before real use:
- A cryptographer's review of the offline scheme (production mode logs a warning until then), and unlinkable payments (blind signatures or anonymous credentials) if privacy matters.
- Per-user authentication and owner signatures on every spend; KYC tiers from the ledger's own records.
- Real wallets with secure elements and real terminals, so the ledger never holds s or r; offline balance and time caps.
- An independent security review and penetration test.
- Validation against the bank's own policies, merchants and transaction data.
- RBI sign-off (the e₹ framework, programmable-money rules) and DPDP Act 2023 review of what the ledger records about wallet holders.
- Real integrations: RBI's e₹ systems, payment rails, merchant onboarding.
- HSM/KMS for the issuer and wallet keys instead of environment variables.
- An on-call team, SLOs and alerting wired to the metrics above.
