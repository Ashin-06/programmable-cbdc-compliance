"""
FastAPI service for Programmable CBDC (e-Rupee) Policy VM & Offline Double-Spend Guard.

A single in-memory demo ledger. The caller is trusted: there are no per-user accounts or
signatures, so whoever holds the API key can mint, spend any UTXO and state the sender's KYC tier.
Set CBDCGUARD_API_KEY to require it in the X-API-Key header on every endpoint except / and /health
(unset = open, for local use; `python -m cbdcguard serve` refuses a non-loopback host without it).
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path
import threading
from typing import Any
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from cbdcguard.bench import run_benchmark
from cbdcguard.ledger import CBDCLedger, build_demo_ledger
from cbdcguard.policy_vm import PBMPolicy

app = FastAPI(
    title="CBDCGuard — Programmable e-Rupee Policy VM & Offline Double-Spend Guard",
    version="1.0.0",
    description=(
        "Purpose-Bound Money (PBM) Stack VM, Unwrap-on-Settlement Engine, Expiry Clawback, "
        "and Cut-and-Choose Single-Show Polynomial Offline Double-Spend Identity Recovery."
    ),
)

LEDGER: CBDCLedger = build_demo_ledger()
CONSOLE_PATH = Path(__file__).resolve().parent.parent / "web" / "console.html"
API_KEY = os.environ.get("CBDCGUARD_API_KEY")
MAX_BODY_BYTES = 64_000
MAX_AMOUNT = 1e9
_LOCK = threading.Lock()  # ponytail: one global lock around the in-memory ledger; per-account locks if it ever matters

ID = Field(..., min_length=1, max_length=64)
OPT_ID = Field(default=None, min_length=1, max_length=64)


def require_key(x_api_key: str | None = Header(default=None)) -> None:
    if API_KEY and not hmac.compare_digest(x_api_key or "", API_KEY):
        raise HTTPException(401, "missing or wrong X-API-Key")


@app.middleware("http")
async def limit_body(request: Request, call_next):
    if request.method == "POST":
        # Bodiless POSTs (/reset, /offline/sync) are fine; chunked bodies have no length to check
        length = request.headers.get("content-length", "0")
        if "transfer-encoding" in request.headers or not length.isdigit() or int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "body must have a Content-Length of at most 64 KB"}, status_code=413)
    return await call_next(request)


class MintUTXORequest(BaseModel):
    owner_id: str = ID
    amount: float = Field(..., gt=0, le=MAX_AMOUNT, allow_inf_nan=False, examples=[10000.0])
    policy_id: str = Field(default="PBM-AGRI-01", max_length=64)
    utxo_id: str | None = OPT_ID
    custom_policy_name: str | None = Field(default=None, max_length=120)
    allowed_mccs: list[int] | None = Field(default=None, max_length=100)
    blocked_mccs: list[int] | None = Field(default=None, max_length=100)
    allowed_regions: list[str] | None = Field(default=None, max_length=50)
    max_tx_amount: float | None = Field(default=None, gt=0, le=MAX_AMOUNT, allow_inf_nan=False)
    expires_at: int | None = Field(default=None, ge=0)
    unwrap_on_settlement: bool = Field(default=True)
    sponsor_id: str = Field(default="CENTRAL-BANK-ISSUER", max_length=64)


class TransferUTXORequest(BaseModel):
    utxo_id: str = ID
    merchant_id: str = ID
    amount: float | None = Field(default=None, gt=0, le=MAX_AMOUNT, allow_inf_nan=False)
    timestamp: int = Field(default=1_760_000_000, ge=0)
    sender_kyc_tier: int = Field(default=2, ge=0, le=5)  # asserted by the trusted caller


class SweepRequest(BaseModel):
    current_timestamp: int = Field(default=1_760_000_000, ge=0)


class OfflineMintRequest(BaseModel):
    wallet_id: str = ID
    amount: float = Field(..., gt=0, le=MAX_AMOUNT, allow_inf_nan=False, examples=[1000.0])
    coin_id: str | None = OPT_ID


class OfflineSpendRequest(BaseModel):
    wallet_id: str = ID
    coin_id: str = ID
    merchant_id: str = ID
    timestamp: int = Field(default=1_760_005_000, ge=0)
    nonce: str | None = Field(default=None, min_length=1, max_length=64)
    simulate_double_spend: bool = Field(default=False)


@app.get("/", response_class=HTMLResponse)
def get_console() -> HTMLResponse:
    if CONSOLE_PATH.exists():
        return HTMLResponse(content=CONSOLE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>CBDCGuard Console</h1><p>web/console.html not found.</p>")


@app.get("/health")
def get_health() -> dict[str, Any]:
    return {"status": "ok", "service": "cbdcguard", "port": 8018}


@app.get("/state", dependencies=[Depends(require_key)])
def get_state() -> dict[str, Any]:
    with _LOCK:
        return LEDGER.snapshot()


@app.post("/reset", dependencies=[Depends(require_key)])
def reset_state() -> dict[str, Any]:
    global LEDGER
    with _LOCK:
        LEDGER = build_demo_ledger()
        return {"status": "reset", "state": LEDGER.snapshot()}


@app.post("/cbdc/mint", dependencies=[Depends(require_key)])
def mint_cbdc(req: MintUTXORequest) -> dict[str, Any]:
    with _LOCK:
        return _mint_cbdc(req)


def _mint_cbdc(req: MintUTXORequest) -> dict[str, Any]:
    try:
        custom_policy: PBMPolicy | None = None
        if req.allowed_mccs is not None or req.allowed_regions is not None or req.expires_at is not None:
            pid = req.policy_id if req.policy_id not in LEDGER.policies else f"PBM-CUSTOM-{uuid.uuid4().hex[:6].upper()}"
            custom_policy = PBMPolicy(
                policy_id=pid,
                name=req.custom_policy_name or f"Custom PBM Policy ({pid})",
                description="Custom Purpose-Bound Money policy minted via API",
                sponsor_id=req.sponsor_id,
                allowed_mccs=set(req.allowed_mccs or []),
                blocked_mccs=set(req.blocked_mccs if req.blocked_mccs is not None else [7995, 6011]),
                allowed_regions=set(req.allowed_regions or []),
                max_tx_amount=req.max_tx_amount,
                expires_at=req.expires_at,
                unwrap_on_settlement=req.unwrap_on_settlement,
            )
        utxo = LEDGER.mint_utxo(
            owner_id=req.owner_id,
            amount=req.amount,
            policy_id=req.policy_id,
            utxo_id=req.utxo_id,
            custom_policy=custom_policy,
        )
        return {
            "status": "minted",
            "utxo": utxo.to_dict(),
            "policy": LEDGER.policies[utxo.policy_id].to_dict(),
        }
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/cbdc/transfer", dependencies=[Depends(require_key)])
def transfer_cbdc(req: TransferUTXORequest) -> dict[str, Any]:
    try:
        with _LOCK:
            outcome = LEDGER.transfer_utxo(
                utxo_id=req.utxo_id,
                merchant_id=req.merchant_id,
                amount=req.amount,
                timestamp=req.timestamp,
                sender_kyc_tier=req.sender_kyc_tier,
            )
        return outcome.to_dict()
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/cbdc/sweep", dependencies=[Depends(require_key)])
def sweep_expired(req: SweepRequest) -> dict[str, Any]:
    with _LOCK:
        swept = LEDGER.sweep_expired_utxos(current_timestamp=req.current_timestamp)
    return {"swept_count": len(swept), "swept_utxos": swept}


@app.post("/offline/mint", dependencies=[Depends(require_key)])
def mint_offline(req: OfflineMintRequest) -> dict[str, Any]:
    try:
        with _LOCK:
            coin = LEDGER.mint_offline_coin(
                wallet_id=req.wallet_id,
                amount=req.amount,
                coin_id=req.coin_id,
            )
        return {"status": "minted", "coin": coin.to_public_dict()}
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/offline/spend", dependencies=[Depends(require_key)])
def spend_offline(req: OfflineSpendRequest) -> dict[str, Any]:
    try:
        with _LOCK:
            packet = LEDGER.execute_offline_spend(
                wallet_id=req.wallet_id,
                coin_id=req.coin_id,
                merchant_id=req.merchant_id,
                timestamp=req.timestamp,
                nonce=req.nonce,
                simulate_double_spend=req.simulate_double_spend,
            )
            return {
                "status": "queued_for_sync",
                "packet": packet.to_dict(),
                "pending_offline_count": len(LEDGER.pending_offline_packets),
            }
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/offline/sync", dependencies=[Depends(require_key)])
def sync_offline() -> dict[str, Any]:
    with _LOCK:
        return LEDGER.sync_offline_batch()


@app.get("/bench", dependencies=[Depends(require_key)])
def get_benchmark() -> dict[str, Any]:
    return run_benchmark()
