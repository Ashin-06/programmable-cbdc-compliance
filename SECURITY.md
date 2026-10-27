# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, through GitHub's private vulnerability
reporting on this repository (Security → Report a vulnerability) or by contacting the
maintainer, [@Ashin-06](https://github.com/Ashin-06), directly. Do not open a public issue.

Include what you found, how to reproduce it and what an attacker could do with it. You should
get an acknowledgement within 5 working days. Please give us 90 days to fix an issue before
disclosing it, and don't test against anyone else's deployment.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| < 1.0 | no (prototype releases) |

## Scope

In scope: the ledger service, the policy VM, the offline coin scheme (`offline.py`), the sealing of
the simulated wallets' secrets, the container image and the CI configuration in this repository.

Out of scope: your reverse proxy or TLS setup, and findings that need an already-compromised host
or a leaked API key with the matching role.

**The offline e-cash scheme is unreviewed cryptography.** Its group arithmetic is libsodium's
Ed25519 (through PyNaCl) and its signatures and sealing use `cryptography`, but the protocol is
hand-written and has not been reviewed by a cryptographer. It does not make payments unlinkable,
and double-spend detection happens after the fact. The service logs a warning saying so when it
starts in production mode, and the `/offline/*` endpoints return the same warning. Do not issue real
money with it.

This project has **not** had an independent security review or penetration test.
