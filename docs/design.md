# Design

## Policy machine

`policy_vm.py` compiles a policy into a short list of stack-machine instructions:
- an expiry check;
- a minimum KYC tier;
- blocked merchant category codes (gambling 7995, ATM cash-out 6011);
- allowed merchant categories;
- allowed regions;
- a per-payment ceiling;
- a verified-merchant requirement;
- an unwrap flag.

Running it returns allow or deny, the rule that failed and a trace of the instructions.

## Ledger

`ledger.py` spends UTXOs against these policies, creates change UTXOs that keep the original policy, turns tokens into ordinary money when a verified merchant receives them, and returns expired UTXOs to the sponsor. Reused UTXO, coin, policy, merchant and wallet IDs are rejected, and money is integer paise throughout. Spends, sweeps, coin settlement and packet claims are guarded in SQL, so replicas sharing a database can't spend a UTXO or pay a coin twice.

## Offline coins

`offline.py`:
- Withdrawal: a wallet has a secret s and public key S = s·G. For each coin it picks a random r with R = r·G, and the issuer signs the coin's ID, wallet, counter, amount, S and R with Ed25519.
- Payment: the terminal derives a challenge x from its merchant ID, the time, its nonce and the coin ID. The wallet answers y = s·x + r, and the terminal checks the issuer's signature and that y·G = x·S + R, with no network.
- Sync: the ledger only pays coins it issued, and pays the amount it recorded. A packet submitted twice is paid once. Two different answers for the same coin give s = (y₁ − y₂)/(x₁ − x₂); the ledger checks s against S and takes the wallet's collateral.
- A counter in the wallet's secure element is supposed to stop it answering twice. The double-spend path is simulated by turning that guard off.

Because the service also plays the wallets, it stores each wallet's s and each coin's r, sealed with AES-256-GCM. A real ledger would never hold them.

## Results

`python -m cbdcguard bench`:

| Check | Result |
|---|---|
| 200 policy decisions (75 allowed, 25 each of blocked category, wrong category, wrong region, over limit, expired) | 200 of 200 as expected |
| allowed spends turned into ordinary money | 75 of 75 |
| expired spend attempts returned to the sponsor | 25 of 25 |
| offline double spends detected, with s recovered and checked | 25 of 25 |
| honest offline wallets flagged or penalised | 0 of 75 |

These are consistency checks on hand-built cases, not measurements. Recovering s from two answers always works when the challenges differ; that a single answer reveals nothing about s follows from r being random and used once, which a benchmark can't measure.
