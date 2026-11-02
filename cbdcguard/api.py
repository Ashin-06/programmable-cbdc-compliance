"""
FastAPI service for Programmable CBDC (e-Rupee) Policy VM & Offline Double-Spend Guard.

The ledger lives in a database (ledger.py, db.py) and money is integer paise; amounts in
requests are rupees as JSON numbers or decimal strings with at most two decimals, and amounts
in responses are rupee strings next to `*_paise` integers. Settings come from CBDCGUARD_*
environment variables (ops.py).

The caller is trusted: there are no per-user accounts or signatures on spends, so whoever holds
a key with the `payments` role can spend any UTXO and state the sender's KYC tier.
"""

from __future__ import annotations

from decimal import Decimal
import logging
import os
from pathlib import Path
from typing import Any
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from cbdcguard import db, ops
from cbdcguard.bench import run_benchmark
from cbdcguard.ledger import CBDCLedger, seed_demo
from cbdcguard.money import to_paise
from cbdcguard.policy_vm import PBMPolicy

log = logging.getLogger("cbdcguard.api")
OFFLINE_WARNING = ("the offline e-cash scheme is hand-written and has not been reviewed by a cryptographer; "
                   "do not issue real money with it")

settings = ops.load_settings()
ops.setup_logging(settings.log_level)
# before touching the database, so a refused start leaves no trace
if settings.production and os.environ.get("CBDCGUARD_ACCEPT_UNREVIEWED_CRYPTO", "").strip().lower() != "yes":
    raise ops.ConfigError(OFFLINE_WARNING + "; set CBDCGUARD_ACCEPT_UNREVIEWED_CRYPTO=yes to run anyway")
store = db.connect(settings.database_url)
LEDGER = CBDCLedger(
    engine=store,
    issuer_key=Ed25519PrivateKey.from_private_bytes(settings.secret["ISSUER_KEY"]),
    previous_issuer_keys=tuple(Ed25519PrivateKey.from_private_bytes(k) for k in settings.previous["ISSUER_KEY"]),
    wallet_key=settings.secret["WALLET_KEY"],
    previous_wallet_keys=settings.previous["WALLET_KEY"],
)
if LEDGER.is_empty():
    try:
        seed_demo(LEDGER)  # a fresh database gets the demo merchants, vouchers and wallets
    except ValueError:
        log.info("demo data already seeded by another replica")
if settings.production:
    log.warning("UNREVIEWED CRYPTOGRAPHY: " + OFFLINE_WARNING)

app = FastAPI(
    title="CBDCGuard — Programmable e-Rupee Policy VM & Offline Double-Spend Guard",
    version="1.0.0",
    description=(
        "Purpose-Bound Money (PBM) Stack VM, Unwrap-on-Settlement Engine, Expiry Clawback, "
        "and Single-Show Offline Double-Spend Identity Recovery."
    ),
)
ops.install(app, settings, {"database": lambda: store.connect().close()})

CONSOLE_PATH = Path(__file__).resolve().parent.parent / "web" / "console.html"
MAX_AMOUNT = Decimal("1000000000")  # rupees

ID = Field(..., min_length=1, max_length=64)
OPT_ID = Field(default=None, min_length=1, max_length=64)


def _amount(**kw: Any) -> Any:
    return Field(gt=0, le=MAX_AMOUNT, decimal_places=2, allow_inf_nan=False, **kw)


class MintUTXORequest(BaseModel):
    owner_id: str = ID
    amount: Decimal = _amount(examples=["10000.00"])
    policy_id: str = Field(default="PBM-AGRI-01", max_length=64)
    utxo_id: str | None = OPT_ID
    custom_policy_name: str | None = Field(default=None, max_length=120)
    allowed_mccs: list[int] | None = Field(default=None, max_length=100)
    blocked_mccs: list[int] | None = Field(default=None, max_length=100)
    allowed_regions: list[str] | None = Field(default=None, max_length=50)
    max_tx_amount: Decimal | None = _amount(default=None)
    expires_at: int | None = Field(default=None, ge=0)
    unwrap_on_settlement: bool = Field(default=True)
    sponsor_id: str = Field(default="CENTRAL-BANK-ISSUER", max_length=64)


class TransferUTXORequest(BaseModel):
    utxo_id: str = ID
    merchant_id: str = ID
    amount: Decimal | None = _amount(default=None)
    timestamp: int = Field(default=1_760_000_000, ge=0)
    sender_kyc_tier: int = Field(default=2, ge=0, le=5)  # asserted by the trusted caller


class SweepRequest(BaseModel):
    current_timestamp: int = Field(default=1_760_000_000, ge=0)


class OfflineMintRequest(BaseModel):
    wallet_id: str = ID
    amount: Decimal = _amount(examples=["1000.00"])
    coin_id: str | None = OPT_ID


class OfflineSpendRequest(BaseModel):
    wallet_id: str = ID
    coin_id: str = ID
    merchant_id: str = ID
    timestamp: int = Field(default=1_760_005_000, ge=0)
    nonce: str | None = Field(default=None, min_length=1, max_length=64)
    simulate_double_spend: bool = Field(default=False)


def _refused(exc: Exception) -> HTTPException:
    # The ledger's messages name IDs and amounts only (KeyError's str() would add quotes)
    return HTTPException(status_code=400, detail=exc.args[0] if exc.args else "refused")


@app.get("/", response_class=HTMLResponse)
def get_console() -> HTMLResponse:
    if CONSOLE_PATH.exists():
        return HTMLResponse(content=CONSOLE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>CBDCGuard Console</h1><p>web/console.html not found.</p>")


@app.get("/state")
def get_state(ident: dict = Depends(ops.require("read"))) -> dict[str, Any]:
    return LEDGER.snapshot()


@app.post("/reset")
def reset_state(ident: dict = Depends(ops.require("reset"))) -> dict[str, Any]:
    if settings.production:
        raise HTTPException(status_code=403, detail="reset deletes the ledger and is disabled in production")
    LEDGER.wipe()
    seed_demo(LEDGER)
    return {"status": "reset", "state": LEDGER.snapshot()}


@app.post("/cbdc/mint")
def mint_cbdc(req: MintUTXORequest, ident: dict = Depends(ops.require("mint"))) -> dict[str, Any]:
    try:
        custom_policy: PBMPolicy | None = None
        if req.allowed_mccs is not None or req.allowed_regions is not None or req.expires_at is not None:
            pid = req.policy_id if LEDGER.policy(req.policy_id) is None else f"PBM-CUSTOM-{uuid.uuid4().hex[:6].upper()}"
            custom_policy = PBMPolicy(
                policy_id=pid,
                name=req.custom_policy_name or f"Custom PBM Policy ({pid})",
                description="Custom Purpose-Bound Money policy minted via API",
                sponsor_id=req.sponsor_id,
                allowed_mccs=set(req.allowed_mccs or []),
                blocked_mccs=set(req.blocked_mccs if req.blocked_mccs is not None else [7995, 6011]),
                allowed_regions=set(req.allowed_regions or []),
                max_tx_paise=to_paise(req.max_tx_amount) if req.max_tx_amount is not None else None,
                expires_at=req.expires_at,
                unwrap_on_settlement=req.unwrap_on_settlement,
            )
        utxo = LEDGER.mint_utxo(
            owner_id=req.owner_id,
            amount_paise=to_paise(req.amount),
            policy_id=req.policy_id,
            utxo_id=req.utxo_id,
            custom_policy=custom_policy,
        )
    except (KeyError, ValueError) as exc:
        raise _refused(exc) from exc
    ops.DECISIONS.labels(decision="minted").inc()
    return {"status": "minted", "utxo": utxo.to_dict(), "policy": LEDGER.policy(utxo.policy_id).to_dict()}


@app.post("/cbdc/transfer")
def transfer_cbdc(req: TransferUTXORequest, ident: dict = Depends(ops.require("spend"))) -> dict[str, Any]:
    try:
        outcome = LEDGER.transfer_utxo(
            utxo_id=req.utxo_id,
            merchant_id=req.merchant_id,
            amount_paise=to_paise(req.amount) if req.amount is not None else None,
            timestamp=req.timestamp,
            sender_kyc_tier=req.sender_kyc_tier,
        )
    except (KeyError, ValueError) as exc:
        raise _refused(exc) from exc
    decision = "approved" if outcome.approved else "swept" if outcome.swept_to_sponsor else "blocked"
    ops.DECISIONS.labels(decision=decision).inc()
    return outcome.to_dict()


@app.post("/cbdc/sweep")
def sweep_expired(req: SweepRequest, ident: dict = Depends(ops.require("sweep"))) -> dict[str, Any]:
    swept = LEDGER.sweep_expired_utxos(current_timestamp=req.current_timestamp)
    ops.DECISIONS.labels(decision="swept").inc(len(swept))
    return {"swept_count": len(swept), "swept_utxos": swept}


@app.post("/offline/mint")
def mint_offline(req: OfflineMintRequest, ident: dict = Depends(ops.require("mint"))) -> dict[str, Any]:
    try:
        coin = LEDGER.mint_offline_coin(wallet_id=req.wallet_id, amount_paise=to_paise(req.amount), coin_id=req.coin_id)
    except (KeyError, ValueError) as exc:
        raise _refused(exc) from exc
    return {"status": "minted", "coin": coin.to_public_dict(), "warning": OFFLINE_WARNING}


@app.post("/offline/spend")
def spend_offline(req: OfflineSpendRequest, ident: dict = Depends(ops.require("spend"))) -> dict[str, Any]:
    try:
        packet = LEDGER.execute_offline_spend(
            wallet_id=req.wallet_id,
            coin_id=req.coin_id,
            merchant_id=req.merchant_id,
            timestamp=req.timestamp,
            nonce=req.nonce,
            simulate_double_spend=req.simulate_double_spend,
        )
    except (KeyError, ValueError) as exc:
        raise _refused(exc) from exc
    return {
        "status": "queued_for_sync",
        "packet": packet.to_dict(),
        "pending_offline_count": LEDGER.pending_count(),
        "warning": OFFLINE_WARNING,
    }


@app.post("/offline/sync")
def sync_offline(ident: dict = Depends(ops.require("sync"))) -> dict[str, Any]:
    report = LEDGER.sync_offline_batch()
    for kind, n in (("offline_settled", report["settled_count"]), ("double_spend", report["double_spends_detected"]),
                    ("offline_rejected", report["rejected_count"])):
        ops.DECISIONS.labels(decision=kind).inc(n)
    return {**report, "warning": OFFLINE_WARNING}


@app.get("/bench")
def get_benchmark(ident: dict = Depends(ops.require("bench"))) -> dict[str, Any]:
    return run_benchmark()  # on its own in-memory ledger; the service's ledger is untouched
