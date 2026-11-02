# Programmable CBDC Compliance

A working model of two features discussed for retail digital currencies such as the e-rupee:

1. Purpose-bound money: a subsidy or voucher that can only be spent at certain kinds of merchants, in certain regions, up to a limit and before an expiry date. When a verified merchant receives it, it becomes ordinary money; if it expires unspent, it goes back to the sponsor.
2. Offline payments with double-spend detection: a wallet can pay a merchant terminal with no network. If someone copies the wallet and spends the same coin twice, the two payment records reveal the wallet's secret key when the merchants sync, which proves the double spend and identifies the wallet.

It is a simulation. The policies, merchants and wallets are made up, and the example policies are not RBI rules or the terms of any real scheme. The offline payment protocol is written in this project on top of libsodium and `cryptography` and has not been reviewed by a cryptographer.

## Features

- Spending policies compiled into small programs: expiry, minimum KYC tier, blocked and allowed merchant categories, regions, per-payment limit and verified merchants. Every decision comes with the rule that failed and a trace.
- A ledger that keeps the policy on change, converts tokens to ordinary money at verified merchants and returns expired money to the sponsor.
- Offline coins signed by the issuer, with challenge-response payments that a terminal can check without a network.
- Double-spend detection at sync that recovers the wallet's key and takes its collateral.
- Money stored as integer paise, and spends guarded in the database so two replicas can't spend the same coin.

How the policy machine and offline coins work is described in [docs/design.md](docs/design.md).

## Quick start

```bash
pip install -r requirements-dev.lock && pip install -e .
python -m pytest -q                      # 41 tests
python -m cbdcguard bench
python -m cbdcguard serve                # API and console on http://127.0.0.1:8018
```

To run it in a container:

```bash
docker build -t programmable-cbdc-compliance .
python -m cbdcguard.ops keygen           # prints an API key, its hash, and issuer and wallet keys
docker run -d -p 8018:8018 -v cbdcguard-data:/data -e CBDCGUARD_API_KEYS='{"sha256:...": {"user": "ops", "role": "admin"}}' \
  -e CBDCGUARD_ISSUER_KEY=... -e CBDCGUARD_WALLET_KEY=... -e CBDCGUARD_ACCEPT_UNREVIEWED_CRYPTO=yes \
  programmable-cbdc-compliance
```

## API

| Endpoint | Purpose |
|---|---|
| `POST /cbdc/mint` | issue purpose-bound money |
| `POST /cbdc/transfer` | spend it against its policy |
| `POST /cbdc/sweep` | return expired money to sponsors |
| `POST /offline/mint`, `/offline/spend`, `/offline/sync` | issue, spend and settle offline coins |
| `GET /state` | the ledger |
| `POST /reset`, `GET /bench` | demo reset (refused in production) and benchmark |
| `GET /healthz`, `/readyz`, `/metrics` | health, readiness and Prometheus metrics |

Amounts are rupees with at most two decimals. API keys carry a role: `issuer` mints, sweeps and syncs; `payments` spends; `auditor` reads the ledger; `monitor` reads metrics; `admin` can do everything.

## Results

| Check | Result |
|---|---|
| 200 policy decisions across every rule | all as expected |
| Allowed spends converted to ordinary money | 75 of 75 |
| Expired money returned to the sponsor | 25 of 25 |
| Offline double spends caught, with the wallet key recovered | 25 of 25 |
| Honest offline wallets wrongly penalised | 0 of 75 |

These are consistency checks on hand-built cases, not measurements. No CBDC transaction data is public.

## Configuration

| Variable | Purpose |
|---|---|
| `CBDCGUARD_ENV=production` | refuse to start without API keys, the issuer and wallet keys and a database |
| `CBDCGUARD_ACCEPT_UNREVIEWED_CRYPTO=yes` | required in production: acknowledges that the offline e-cash scheme is hand-written and unreviewed |
| `CBDCGUARD_ISSUER_KEY` | Ed25519 seed the issuer signs coins with |
| `CBDCGUARD_WALLET_KEY` | key that seals the simulated wallets' secrets |
| `CBDCGUARD_API_KEYS` / `CBDCGUARD_KEYS_FILE` | hashed API keys with roles |
| `CBDCGUARD_DATABASE_URL` | `sqlite:///...` or `postgresql://...` |

## Limitations

- It is a simulation with no connection to a real CBDC system. The service plays the wallets and terminals itself, so it holds wallet secrets that a real ledger never would.
- Spends are not signed by their owners: a `payments` key can spend any balance and state the sender's KYC tier.
- Offline payments are linkable, because every coin carries the wallet's ID and public key. Private offline cash would need blind signatures or anonymous credentials.
- A double spend is only detected afterwards, and recovery depends on collateral the wallet may not have.
- The offline protocol has not been reviewed by a cryptographer, and the code has not had an independent security review.

See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).

## License

MIT. See [LICENSE](LICENSE).
