"""FastAPI service for Programmable CBDC (e-Rupee) Policy VM & Offline Double-Spend Guard."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
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


class MintUTXORequest(BaseModel):
    owner_id: str = Field(..., examples=["FARMER-KISAN-01"])
    amount: float = Field(..., gt=0, examples=[10000.0])
    policy_id: str = Field(default="PBM-AGRI-01", examples=["PBM-AGRI-01"])
    utxo_id: str | None = Field(default=None)
    custom_policy_name: str | None = Field(default=None)
    allowed_mccs: list[int] | None = Field(default=None)
    blocked_mccs: list[int] | None = Field(default=None)
    allowed_regions: list[str] | None = Field(default=None)
    max_tx_amount: float | None = Field(default=None)
    expires_at: int | None = Field(default=None)
    unwrap_on_settlement: bool = Field(default=True)
    sponsor_id: str = Field(default="RBI-TREASURY")


class TransferUTXORequest(BaseModel):
    utxo_id: str = Field(..., examples=["UTXO-AGRI-101"])
    merchant_id: str = Field(..., examples=["M-AGRI-PUNE"])
    amount: float | None = Field(default=None, examples=[5000.0])
    timestamp: int = Field(default=1_760_000_000)
    sender_kyc_tier: int = Field(default=2)


class SweepRequest(BaseModel):
    current_timestamp: int = Field(default=1_760_000_000)


class OfflineMintRequest(BaseModel):
    wallet_id: str = Field(..., examples=["WALLET-NFC-01"])
    amount: float = Field(..., gt=0, examples=[1000.0])
    coin_id: str | None = Field(default=None)


class OfflineSpendRequest(BaseModel):
    wallet_id: str = Field(..., examples=["WALLET-NFC-02"])
    coin_id: str = Field(..., examples=["OFFCOIN-NFC02-001"])
    merchant_id: str = Field(..., examples=["M-AGRI-PUNE"])
    timestamp: int = Field(default=1_760_005_000)
    nonce: str | None = Field(default=None)
    simulate_double_spend: bool = Field(default=False)


@app.get("/", response_class=HTMLResponse)
def get_console() -> HTMLResponse:
    if CONSOLE_PATH.exists():
        return HTMLResponse(content=CONSOLE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>CBDCGuard Console</h1><p>web/console.html not found.</p>")


@app.get("/health")
def get_health() -> dict[str, Any]:
    return {"status": "ok", "service": "cbdcguard", "port": 8018}


@app.get("/state")
def get_state() -> dict[str, Any]:
    return LEDGER.snapshot()


@app.post("/reset")
def reset_state() -> dict[str, Any]:
    global LEDGER
    LEDGER = build_demo_ledger()
    return {"status": "reset", "state": LEDGER.snapshot()}


@app.post("/cbdc/mint")
def mint_cbdc(req: MintUTXORequest) -> dict[str, Any]:
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


@app.post("/cbdc/transfer")
def transfer_cbdc(req: TransferUTXORequest) -> dict[str, Any]:
    try:
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


@app.post("/cbdc/sweep")
def sweep_expired(req: SweepRequest) -> dict[str, Any]:
    swept = LEDGER.sweep_expired_utxos(current_timestamp=req.current_timestamp)
    return {"swept_count": len(swept), "swept_utxos": swept}


@app.post("/offline/mint")
def mint_offline(req: OfflineMintRequest) -> dict[str, Any]:
    try:
        coin = LEDGER.mint_offline_coin(
            wallet_id=req.wallet_id,
            amount=req.amount,
            coin_id=req.coin_id,
        )
        return {"status": "minted", "coin": coin.to_public_dict()}
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/offline/spend")
def spend_offline(req: OfflineSpendRequest) -> dict[str, Any]:
    try:
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


@app.post("/offline/sync")
def sync_offline() -> dict[str, Any]:
    return LEDGER.sync_offline_batch()


@app.get("/bench")
def get_benchmark() -> dict[str, Any]:
    return run_benchmark()
