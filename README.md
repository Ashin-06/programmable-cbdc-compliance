# Project 18 — Programmable CBDC (e-Rupee) Policy VM & Cryptographic Offline Double-Spend Guard (`cbdcguard`)

A production-grade reference engine for **Programmable Central Bank Digital Currency (e-Rupee / e₹)** featuring a **Purpose-Bound Money (PBM) Deterministic Stack VM**, **Automatic Merchant Unwrap-on-Settlement**, **Expiry Treasury Clawback**, and **Cut-and-Choose / Single-Show Polynomial Offline Double-Spend Identity Recovery**.

---

## Architecture & Core Modules

1. **`cbdcguard/policy_vm.py` — Purpose-Bound Money (PBM) Policy DSL & Deterministic Stack VM**
   - Compiles declarative spend constraints attached to CBDC token UTXOs into deterministic Stack VM bytecode (`LOAD_CTX`, `PUSH_CONST`, `OP_IN_SET`, `OP_NOT_IN_SET`, `OP_LTE`, `OP_GTE`, `OP_EQ`, `OP_CHECK_EXPIRY`, `OP_ASSERT`, `OP_CHECK_UNWRAP`, `OP_HALT`):
     - `allowed_mccs`: e.g. `{5191, 5261}` (agricultural seeds & fertilizers), `{5411, 5812}` (food/grocery), `{8011, 8062}` (healthcare/hospitals)
     - `blocked_mccs`: e.g. `{7995}` (gambling/betting), `{6011}` (ATM cash-out)
     - `allowed_regions`: e.g. `{"IN-MH", "IN-KA"}`
     - `max_tx_amount`: per-transaction ceiling
     - `expires_at`: timestamp after which unspent subsidy/voucher auto-sweeps back to the issuing treasury/sponsor
     - `unwrap_on_settlement`: when a verified merchant with matching MCC/region receives the purpose-bound CBDC, it automatically unwraps into general-purpose commercial e-Rupee (`PBM-GENERAL`)

2. **`cbdcguard/offline.py` — Cut-and-Choose / Single-Show Polynomial Offline Double-Spend Guard**
   - Solves the central bank offline NFC payment privacy vs. double-spend accountability dilemma in a prime-order Schnorr subgroup $G_q \subset \mathbb{Z}_p^*$ ($p = 2q + 1$, generator $g = 4$):
     - **Minting Commitment**: Each offline coin $C$ with monotonic counter $c$ commits to a random line $L(x) = (s \cdot x + r) \bmod q$ where $s \in \mathbb{F}_q$ is the user's secret identity scalar and $r \in \mathbb{F}_q$ is a per-coin random blinding scalar, publishing $(g^s \bmod p, g^r \bmod p)$.
     - **Offline Terminal Verification**: The merchant POS terminal computes $x = H(\text{merchant\_id} \parallel \text{timestamp} \parallel \text{nonce}) \bmod q$, receives $y = (s \cdot x + r) \bmod q$, and checks offline:
       $$g^y \equiv (g^s)^x \cdot g^r \pmod p$$
     - **Single-Show Privacy**: A single honest spend $(x_1, y_1)$ information-theoretically hides $s$ behind the one-time pad $r \in \mathbb{F}_q$ (**0% key leakage**).
     - **Double-Spend Identity Exposure**: If a malicious user clones their Secure Element or rolls back counter $c$ to spend the same coin twice with challenges $x_1 \ne x_2$, batch synchronization recovers:
       $$s = (y_1 - y_2) \cdot (x_1 - x_2)^{-1} \bmod q$$
       unmasking the exact spender secret $s$ with **100% mathematical certainty** and slashing their escrow collateral.

3. **`cbdcguard/ledger.py` & `cbdcguard/bench.py` — UTXO Ledger & 200+100 Benchmark Suite**
   - Tracks UTXO minting, partial spends with policy-bound change, automatic unwrap on merchant settlement, expiry clawback, and offline batch synchronization with double-spend slashing.
   - Benchmarks **200 programmable CBDC transactions** + **100 offline transactions** (75 honest single spends + 25 double-spend attacks), proving **100% policy enforcement**, **100% secret key recovery on double-spends**, and **0% key leakage on honest spends**.

4. **`cbdcguard/api.py` & `web/console.html` — FastAPI Service & Interactive Console (Port `8018`)**
   - `GET /` — Interactive Programmable CBDC & Offline Double-Spend Guard Web Console
   - `POST /cbdc/mint` — Mint programmable CBDC UTXO
   - `POST /cbdc/transfer` — Evaluate PBM Policy Stack VM & execute transfer
   - `POST /cbdc/sweep` — Claw back expired UTXOs to issuing sponsor
   - `POST /offline/spend` — Sign & verify offline NFC polynomial proof
   - `POST /offline/sync` — Batch sync offline transcripts & slash double-spenders
   - `GET /bench` — Run 200 programmable + 100 offline benchmark suite

---

## Quickstart

```bash
# Run test suite
python -m pytest -q

# Run CLI benchmark (200 programmable CBDC + 100 offline transactions)
python -m cbdcguard bench

# Launch FastAPI server & interactive console on port 8018
python -m cbdcguard serve --port 8018
```
