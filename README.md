# Programmable CBDC Compliance (`cbdcguard`)

A model of two ideas discussed for retail digital currencies such as the e-rupee:

1. **Purpose-bound money.** A subsidy or voucher token that can only be spent at certain kinds of merchants, in certain regions, up to a limit, before an expiry date. When a verified merchant receives it, it turns into ordinary money, and if it expires unspent it goes back to the sponsor.
2. **Offline payments with double-spend detection.** A wallet can pay a merchant terminal with no network. If someone clones the wallet and spends the same coin twice, the two payment records together reveal the wallet's secret key when the merchants later sync, which proves the double spend and identifies who did it.

Everything is an in-memory simulation. Policies, merchants and wallets are made up; the preset policies are generic examples, not RBI rules or the terms of any real scheme.

> **The offline scheme is a reference implementation.** Its group arithmetic is libsodium's Ed25519 (via PyNaCl) and its signatures use `cryptography`, but the protocol code is hand-written and unreviewed. It is not a design anyone should issue currency with.

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

Running it returns an allow/deny decision, the violation code, and an instruction trace. The ledger (`ledger.py`) spends UTXOs against these policies, creates change UTXOs that keep the original policy, unwraps on approved settlement, and sweeps expired UTXOs back to the sponsor. Reused UTXO, coin and policy IDs are rejected, as are non-finite amounts.

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
pip install -r requirements.txt
python -m pytest -q                      # 10 tests
python -m cbdcguard bench
python -m cbdcguard serve --port 8018    # API + console at http://127.0.0.1:8018
```

Endpoints: `GET /state`, `POST /reset`, `POST /cbdc/mint`, `POST /cbdc/transfer`, `POST /cbdc/sweep`, `POST /offline/mint`, `POST /offline/spend`, `POST /offline/sync`, `GET /bench`, `GET /health`. Set `CBDCGUARD_API_KEY` to require it in the `X-API-Key` header (the console has a field for it). Without the key the server runs open, and `serve` refuses to bind a non-loopback address.

## Limits

- **Simulation only.** There's one in-memory ledger, no persistence, and no connection to any real CBDC system.
- **The API trusts its caller.** There are no user accounts or signatures: whoever has the API key can mint any amount, spend any UTXO, and state the sender's KYC tier. A real ledger would require the owner's signature on every spend and take KYC from its own records.
- **Offline payments are not private from merchants or the ledger.** Every coin carries the wallet ID and the same public key S, so all of a wallet's payments are linkable. Unlinkable offline cash needs blind signatures or anonymous credentials (Chaum, Brands), which this doesn't do. The only privacy property is that one payment doesn't reveal s.
- **Double-spend detection is after the fact.** The second merchant has already accepted the coin, and recovery depends on slashing collateral the wallet may not have. Real offline schemes also cap offline balances and how long a wallet may stay offline.
- **Money is float** (rounded to paise in places). A ledger would use integer minor units.
- **Unreviewed cryptographic protocol.** See the note at the top.
