"""CLI entrypoint for cbdcguard (`python -m cbdcguard bench` | `python -m cbdcguard serve --port 8018`)."""

from __future__ import annotations

import argparse
import json
import os
import sys

import uvicorn

from cbdcguard.bench import run_benchmark


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cbdcguard",
        description="Programmable CBDC (e-Rupee) Policy VM & Cryptographic Offline Double-Spend Guard",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("bench", help="Run 200 programmable CBDC + 100 offline transactions benchmark")

    serve_parser = sub.add_parser("serve", help="Start FastAPI server and interactive web console")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=8018, help="Bind port (default: 8018)")

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

    if args.command == "serve":
        if args.host not in ("127.0.0.1", "localhost", "::1") and not os.environ.get("CBDCGUARD_API_KEY"):
            print("Refusing to listen on a non-loopback address without CBDCGUARD_API_KEY set.", file=sys.stderr)
            return 2
        uvicorn.run("cbdcguard.api:app", host=args.host, port=args.port, reload=False)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
