# Threat model

What the ledger service protects, from whom, and what is still open. Written for the 1.0.0 code;
it has not been reviewed by anyone independent.

## The deployment this describes

One service is the central bank's ledger **and** simulates every offline wallet's secure element
and every merchant terminal. A real system would split these: wallets hold s and r in hardware,
terminals verify offline, the ledger only sees issuance records and uploaded packets. Read the
"simulated wallet" rows below with that in mind.

## What it protects

| Asset | Where it lives |
|---|---|
| Ledger state: UTXOs, balances, transfers, sweeps, issued coins, settlements | database tables, money as integer paise |
| Issuer signing key (Ed25519 seed) | `CBDCGUARD_ISSUER_KEY` in the environment / secret store |
| Simulated wallets' secrets s and coin blinding values r | `offline_wallets.sealed_secret`, `offline_coins.sealed_blinding`, AES-256-GCM under `CBDCGUARD_WALLET_KEY` |
| Wallet identities recovered after a double spend | `offline_wallets.recovered_secret_s`, `double_spend_alerts` |
| API keys | callers hold the key; the service holds only SHA-256 hashes |

## Trust boundaries

```
issuer / PSP / auditor ──(TLS at your ingress)──► ledger service ──► database
                                                   (also plays wallets and terminals)
```

1. **Caller → service.** Callers are authenticated by API key; the key's role decides what they may
   do. Within a role the caller is trusted (see below).
2. **Service → database.** Holds the ledger in clear and the wallet secrets sealed.
3. **Wallet ↔ terminal ↔ ledger** (offline). Simulated inside the process; the offline rows below
   describe what would cross these lines.

## Threats and what stops them

| Threat | Mitigation | Residual risk |
|---|---|---|
| Someone invents offline coins | Terminals check the issuer's Ed25519 signature over coin ID, wallet, counter, amount and commitments; sync pays only coins in the ledger's own issuance record, for the recorded amount | **Unreviewed cryptography.** Hand-written protocol code. Production logs a warning; a cryptographer's review is still needed. |
| A wallet spends a coin twice offline | Two answers to different challenges reveal s; sync checks s against S, records an alert and slashes collateral | Detection is after the fact: the second merchant has already accepted the coin, and collateral may not cover it. No offline balance or time cap. |
| A coin is paid twice (retry, replay, two replicas) | Duplicate transcripts are recognised; `settled_coins` primary key; pending packets are claimed with `UPDATE ... WHERE status = 'PENDING'` | — |
| A UTXO is spent twice (race, two replicas) | Spends and sweeps are `UPDATE ... WHERE status = 'UNSPENT'` inside the transaction that writes the outputs | — |
| Rounding creates or destroys money | Integer paise everywhere; floats refused at the API (numbers are parsed as decimals, at most two places) | — |
| Payments are linked to a wallet | — | **Not private.** Every coin carries the wallet ID and the same public key S, so all of a wallet's payments are linkable by merchants and the ledger. Unlinkable cash needs blind signatures or anonymous credentials. |
| A caller with the `payments` role spends someone else's UTXO, or states a false KYC tier | Roles separate issuing from spending; every transfer attempt is recorded | **The caller is trusted.** There are no per-user accounts or signatures on spends. A real ledger would require the owner's signature and take KYC from its own records. |
| Issuer key stolen | Key comes from the secret store, never generated or stored in the code; rotation with `_PREVIOUS` | Whoever holds it can sign coins terminals will accept (sync still pays only coins the ledger issued). Keep it in an HSM in a real system. |
| Database stolen | Simulated wallet secrets are sealed; the AAD binds each to its wallet or coin ID | Balances, transfers and wallet owners are in clear. With the wallet key as well, every simulated wallet can be impersonated and framed for double spends. |
| Stolen API key | Keys per client, revocable; rate limit per key | A stolen `issuer` key can mint any amount until removed |
| Brute-forcing keys | 256-bit random keys; rate limit per address for unknown keys | Rate limit is per process |
| Demo reset wipes the ledger | `/reset` needs the admin role and is refused in production | — |
| Oversized or flooding requests | 64 KB body cap, bounded lists and IDs, per-client token bucket; `/bench` admin only | Per process; several replicas multiply the limit |
| Error messages leak data | Validation errors carry no input; unhandled errors return only a request ID; refusals name IDs only | — |
| Browser attacks on the console | Security headers, CSP, `frame-ancestors 'none'`, server data escaped in the console, no CORS unless origins are listed | The console's CSP allows its own inline script; don't serve it on a shared origin |
| Misconfigured production start | Production refuses to start without hashed keys, both secrets (exact length) and a database; no public bind without keys | Production mode can't check that keys are *good*, only that they exist and have the right shape |

## Not covered

- TLS. Terminate it at your ingress or service mesh; the service speaks plain HTTP.
- Real wallets, secure elements and terminals; any connection to RBI's e₹ systems.
- Constant-time arithmetic and side channels in the offline protocol.
- An insider with database *and* key access.
