"""CLI entrypoint for cbdcguard.

    python -m cbdcguard bench
    python -m cbdcguard serve      (settings: CBDCGUARD_* environment variables, see ops.py)
    python -m cbdcguard migrate    (apply database migrations to CBDCGUARD_DATABASE_URL and exit)
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from cbdcguard.bench import run_benchmark


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cbdcguard",
        description="Programmable CBDC (e-Rupee) Policy VM & Cryptographic Offline Double-Spend Guard",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("bench", help="Run 200 programmable CBDC + 100 offline transactions benchmark")

    serve_parser = sub.add_parser("serve", help="Start FastAPI server and interactive web console")
    serve_parser.add_argument("--host", help="default CBDCGUARD_HOST or 127.0.0.1; any other address needs API keys")
    serve_parser.add_argument("--port", type=int, help="default CBDCGUARD_PORT or 8018")
    sub.add_parser("migrate", help="apply database migrations to CBDCGUARD_DATABASE_URL")

    args = parser.parse_args(argv)

    if args.command == "bench":
        report = run_benchmark()
        print(json.dumps(report, indent=2))
        prog = report["programmable_cbdc"]
        off = report["offline_double_spend_guard"]
        if (
            prog["policy_enforcement_accuracy_pct"] != 100.0
            or off["double_spend_recovery_rate_pct"] != 100.0
            or off["honest_wallets_flagged_rate_pct"] != 0.0
        ):
            return 1
        return 0

    if args.command == "migrate":
        from cbdcguard import db, ops

        applied = db.migrate(db.engine(ops.load_settings().database_url))
        print(*(applied or ["up to date"]), sep="\n")
        return 0

    if args.command == "serve":
        import uvicorn

        from cbdcguard import ops

        for name, val in (("HOST", args.host), ("PORT", args.port)):
            if val is not None:
                os.environ[f"CBDCGUARD_{name}"] = str(val)
        try:
            settings = ops.load_settings()  # fail here, before uvicorn, with a readable message
        except ops.ConfigError as e:
            sys.exit(f"configuration error: {e}")
        ops.setup_logging(settings.log_level)
        uvicorn.run("cbdcguard.api:app", host=settings.host, port=settings.port, log_config=None, access_log=False)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
