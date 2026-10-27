"""Comprehensive test suite for cbdcguard (Policy VM, Offline Double-Spend Recovery, Ledger, Benchmark, API)."""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from cbdcguard.api import app
from cbdcguard.bench import run_benchmark
from cbdcguard.ledger import build_demo_ledger
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cbdcguard.offline import (
    ED25519_L,
    OfflineWallet,
    public_point,
    recover_double_spend_secret,
)
from cbdcguard.policy_vm import (
    OpCode,
    PolicyCompiler,
    PolicyStackVM,
    SpendContext,
    build_preset_policies,
)


def test_pbm_policy_vm_compilation_and_valid_unwrap() -> None:
    policies = build_preset_policies()
    agri = policies["PBM-AGRI-01"]
    bytecode = PolicyCompiler.compile(agri)
    opcodes = [instr.opcode for instr in bytecode]
    assert OpCode.OP_CHECK_EXPIRY in opcodes
    assert OpCode.OP_NOT_IN_SET in opcodes
    assert OpCode.OP_IN_SET in opcodes
    assert OpCode.OP_CHECK_UNWRAP in opcodes
    assert bytecode[-1].opcode == OpCode.OP_HALT

    ctx = SpendContext(
        merchant_id="M-AGRI-PUNE",
        merchant_mcc=5261,
        merchant_region="IN-MH",
        merchant_verified=True,
        amount_paise=800_000,
        timestamp=1_760_000_000,
        sender_kyc_tier=2,
    )
    res = PolicyStackVM.evaluate(agri, ctx)
    assert res.allowed is True
    assert res.violation_code is None
    assert res.should_unwrap is True
    assert res.gas_used > 0


def test_pbm_policy_vm_blocks_violations() -> None:
    agri = build_preset_policies()["PBM-AGRI-01"]

    # 1. Blocked MCC (7995 gambling)
    res_gamble = PolicyStackVM.evaluate(
        agri,
        SpendContext("M-GAMBLE", 7995, "IN-MH", True, 100_000, 1_760_000_000),
    )
    assert res_gamble.allowed is False
    assert res_gamble.violation_code == "ERR_MCC_BLOCKED"

    # 2. Disallowed MCC (5411 grocery on an agri seed policy)
    res_wrong_mcc = PolicyStackVM.evaluate(
        agri,
        SpendContext("M-GROCERY", 5411, "IN-MH", True, 100_000, 1_760_000_000),
    )
    assert res_wrong_mcc.allowed is False
    assert res_wrong_mcc.violation_code == "ERR_MCC_NOT_ALLOWED"

    # 3. Out-of-region geofence
    res_region = PolicyStackVM.evaluate(
        agri,
        SpendContext("M-AGRI-ASSAM", 5261, "IN-AS", True, 100_000, 1_760_000_000),
    )
    assert res_region.allowed is False
    assert res_region.violation_code == "ERR_REGION_OUT_OF_BOUNDS"

    # 4. Per-transaction ceiling exceeded
    res_ceiling = PolicyStackVM.evaluate(
        agri,
        SpendContext("M-AGRI-PUNE", 5261, "IN-MH", True, 5_000_000, 1_760_000_000),
    )
    assert res_ceiling.allowed is False
    assert res_ceiling.violation_code == "ERR_MAX_TX_AMOUNT_EXCEEDED"

    # 5. Expired token triggers sponsor clawback flag
    res_expired = PolicyStackVM.evaluate(
        agri,
        SpendContext("M-AGRI-PUNE", 5261, "IN-MH", True, 100_000, 1_950_000_000),
    )
    assert res_expired.allowed is False
    assert res_expired.is_expired is True
    assert res_expired.should_sweep_to_sponsor is True
    assert res_expired.violation_code == "ERR_UTXO_EXPIRED_CLAWBACK"


def test_offline_polynomial_single_show_privacy_and_double_spend_recovery() -> None:
    issuer = Ed25519PrivateKey.generate()
    issuer_pub = issuer.public_key()
    wallet = OfflineWallet.create("W-TEST-01", "Test User", collateral_paise=1_000_000)
    coin = wallet.mint_coin(amount_paise=50_000, coin_id="COIN-TEST-01", issuer_key=issuer)

    # Honest first spend at terminal 1
    pkt1 = wallet.sign_offline_spend(
        coin_id=coin.coin_id,
        merchant_id="M-TERM-1",
        timestamp=1_760_000_001,
        nonce="nonce-alpha",
        allow_counter_rollback=False,
    )
    assert pkt1.verify_terminal_proof(issuer_pub) is True

    # Information-theoretic single-show privacy proof:
    # For any arbitrary candidate secret s_fake in F_q, there exists a valid blinding scalar r_fake
    # such that (s_fake * x1 + r_fake) mod q == y1.
    s_fake = (wallet.secret_s + 123456789) % ED25519_L
    r_fake = (pkt1.response_y - s_fake * pkt1.challenge_x) % ED25519_L
    assert (s_fake * pkt1.challenge_x + r_fake) % ED25519_L == pkt1.response_y

    # Hardware counter blocks accidental second spend unless rollback is forced
    with pytest.raises(ValueError, match="Hardware monotonic counter guard"):
        wallet.sign_offline_spend(
            coin_id=coin.coin_id,
            merchant_id="M-TERM-2",
            timestamp=1_760_000_002,
            nonce="nonce-beta",
            allow_counter_rollback=False,
        )

    # Simulated counter rollback / cloned Secure Element spend at terminal 2
    pkt2 = wallet.sign_offline_spend(
        coin_id=coin.coin_id,
        merchant_id="M-TERM-2",
        timestamp=1_760_000_002,
        nonce="nonce-beta",
        allow_counter_rollback=True,
    )
    assert pkt2.verify_terminal_proof(issuer_pub) is True
    assert pkt1.challenge_x != pkt2.challenge_x

    # Central bank interpolates s = (y1 - y2) * (x1 - x2)^(-1) mod q
    s_rec, r_rec = recover_double_spend_secret(
        pkt1.challenge_x, pkt1.response_y, pkt2.challenge_x, pkt2.response_y
    )
    assert s_rec == wallet.secret_s
    assert r_rec == coin.blinding_r
    assert public_point(s_rec) == wallet.commitment_s


def test_ledger_unwrap_on_settlement_and_expiry_clawback() -> None:
    ledger = build_demo_ledger()

    # Partial spend of Agri UTXO (₹5,000 of ₹12,000) at verified Pune Agri merchant
    outcome = ledger.transfer_utxo("UTXO-AGRI-101", "M-AGRI-PUNE", amount_paise=500_000)
    assert outcome.approved is True
    assert outcome.unwrapped is True
    assert outcome.new_merchant_utxo_id is not None
    assert outcome.change_utxo_id is not None

    # Merchant UTXO is now unwrapped into PBM-GENERAL and can be spent at Grocery (MCC 5411)
    merchant_utxo = ledger.utxo(outcome.new_merchant_utxo_id)
    assert merchant_utxo.policy_id == "PBM-GENERAL"
    assert merchant_utxo.unwrapped_from_policy == "PBM-AGRI-01"

    second_hop = ledger.transfer_utxo(merchant_utxo.utxo_id, "M-FOOD-MUM", amount_paise=200_000)
    assert second_hop.approved is True

    # Farmer's change UTXO still carries PBM-AGRI-01 and is blocked at Grocery (MCC 5411)
    change_utxo = ledger.utxo(outcome.change_utxo_id)
    assert change_utxo.policy_id == "PBM-AGRI-01"
    blocked_change = ledger.transfer_utxo(change_utxo.utxo_id, "M-FOOD-MUM", amount_paise=100_000)
    assert blocked_change.approved is False
    assert blocked_change.eval_result.violation_code == "ERR_MCC_NOT_ALLOWED"

    # Expired UTXO-EXP-104 auto-sweeps to sponsor on spend attempt
    exp_outcome = ledger.transfer_utxo("UTXO-EXP-104", "M-AGRI-PUNE", amount_paise=400_000, timestamp=1_760_000_000)
    assert exp_outcome.approved is False
    assert exp_outcome.swept_to_sponsor is True
    assert ledger.utxo("UTXO-EXP-104").status == "SWEPT_EXPIRED"


def test_full_benchmark_200_programmable_and_100_offline() -> None:
    report = run_benchmark()
    prog = report["programmable_cbdc"]
    off = report["offline_double_spend_guard"]

    assert prog["total_transactions"] == 200
    assert prog["policy_enforcement_accuracy_pct"] == 100.0
    assert prog["unwrapped_on_settlement"] == 75
    assert prog["expired_auto_swept"] == 25

    assert off["total_offline_scenarios"] == 100
    assert off["honest_single_spends"] == 75
    assert off["double_spend_attacks"] == 25
    assert off["double_spends_detected"] == 25
    assert off["exact_secret_keys_recovered"] == 25
    assert off["double_spend_recovery_rate_pct"] == 100.0
    assert off["honest_wallets_flagged_count"] == 0
    assert off["honest_wallets_flagged_rate_pct"] == 0.0


def test_fastapi_endpoints() -> None:
    client = TestClient(app)

    r_reset = client.post("/reset")
    assert r_reset.status_code == 200

    r_root = client.get("/")
    assert r_root.status_code == 200
    assert "CBDCGuard" in r_root.text

    r_mint = client.post(
        "/cbdc/mint",
        json={"owner_id": "FARMER-TEST", "amount": 6000.0, "policy_id": "PBM-AGRI-01", "utxo_id": "UTXO-API-1"},
    )
    assert r_mint.status_code == 200
    assert r_mint.json()["utxo"]["utxo_id"] == "UTXO-API-1"

    r_tx = client.post(
        "/cbdc/transfer",
        json={"utxo_id": "UTXO-API-1", "merchant_id": "M-AGRI-PUNE", "amount": 6000.0},
    )
    assert r_tx.status_code == 200
    assert r_tx.json()["approved"] is True
    assert r_tx.json()["unwrapped"] is True

    # Offline double-spend via API
    r_s1 = client.post(
        "/offline/spend",
        json={
            "wallet_id": "WALLET-NFC-02",
            "coin_id": "OFFCOIN-NFC02-001",
            "merchant_id": "M-AGRI-PUNE",
            "nonce": "api-nonce-1",
            "simulate_double_spend": False,
        },
    )
    assert r_s1.status_code == 200

    r_s2 = client.post(
        "/offline/spend",
        json={
            "wallet_id": "WALLET-NFC-02",
            "coin_id": "OFFCOIN-NFC02-001",
            "merchant_id": "M-FOOD-MUM",
            "nonce": "api-nonce-2",
            "simulate_double_spend": True,
        },
    )
    assert r_s2.status_code == 200

    r_sync = client.post("/offline/sync")
    assert r_sync.status_code == 200
    sync_data = r_sync.json()
    assert sync_data["double_spends_detected"] == 1
    assert sync_data["double_spend_alerts"][0]["verified_against_commitment"] is True

    r_bench = client.get("/bench")
    assert r_bench.status_code == 200
    assert r_bench.json()["programmable_cbdc"]["policy_enforcement_accuracy_pct"] == 100.0


def test_terminal_rejects_coins_the_issuer_did_not_sign() -> None:
    # The old scheme checked the proof against commitments inside the packet itself, so anyone
    # could invent a coin of any amount. Now the terminal needs the issuer's signature.
    ledger = build_demo_ledger()
    forger = OfflineWallet.create("W-FORGER", "Forger")
    fake = forger.mint_coin(amount_paise=9_999_900, coin_id="OFFCOIN-FAKE")  # no issuer key
    pkt = forger.sign_offline_spend(fake.coin_id, "M-AGRI-PUNE", 1_760_000_000, "n1")
    assert pkt.verify_terminal_proof(ledger.issuer_public_key) is False
    other_issuer = Ed25519PrivateKey.generate()
    fake2 = forger.mint_coin(amount_paise=9_999_900, coin_id="OFFCOIN-FAKE2", issuer_key=other_issuer)
    pkt2 = forger.sign_offline_spend(fake2.coin_id, "M-AGRI-PUNE", 1_760_000_000, "n2")
    assert pkt2.verify_terminal_proof(ledger.issuer_public_key) is False
    # Raising the amount on a genuine coin breaks the signature too
    from dataclasses import replace
    good = ledger.execute_offline_spend("WALLET-NFC-01", "OFFCOIN-NFC01-001", "M-AGRI-PUNE")
    assert good.verify_terminal_proof(ledger.issuer_public_key)
    assert not replace(good, amount_paise=5_000_000).verify_terminal_proof(ledger.issuer_public_key)


def test_sync_pays_only_issued_coins_and_survives_duplicate_transcripts() -> None:
    ledger = build_demo_ledger()
    before = ledger.merchant("M-AGRI-PUNE").balance_paise
    pkt = ledger.execute_offline_spend("WALLET-NFC-01", "OFFCOIN-NFC01-001", "M-AGRI-PUNE", nonce="n-1")
    # The merchant terminal retries the same packet; it used to raise mid-batch (x1 == x2)
    ledger.queue_packet(pkt)
    # A coin signed by the issuer but missing from the ledger's own records is refused
    stray = OfflineWallet.create("WALLET-NFC-01", "same id, other device")
    stray_coin = stray.mint_coin(50_000, coin_id="OFFCOIN-STRAY", issuer_key=ledger.issuer_key)
    ledger.queue_packet(stray.sign_offline_spend(stray_coin.coin_id, "M-AGRI-PUNE", 1, "n-2"))
    report = ledger.sync_offline_batch()
    assert report["settled_count"] == 1
    assert {r["reason"] for r in report["rejected_packets"]} == {"DUPLICATE_SUBMISSION", "NOT_ISSUED_BY_LEDGER"}
    assert report["double_spends_detected"] == 0
    assert ledger.merchant("M-AGRI-PUNE").balance_paise == before + 50_000


def test_ledger_rejects_reused_ids_and_nan_amounts() -> None:
    ledger = build_demo_ledger()
    ledger.transfer_utxo("UTXO-FOOD-102", "M-FOOD-MUM", amount_paise=350_000)
    assert ledger.utxo("UTXO-FOOD-102").status == "SPENT"
    with pytest.raises(ValueError):  # would have reset the spent UTXO to UNSPENT
        ledger.mint_utxo("BENEFICIARY-PRIYA-MH", 350_000, "PBM-FOOD-02", utxo_id="UTXO-FOOD-102")
    with pytest.raises(ValueError):
        ledger.mint_offline_coin("WALLET-NFC-01", 50_000, coin_id="OFFCOIN-NFC01-001")
    with pytest.raises(ValueError):
        ledger.mint_utxo("X", float("nan"))
    with pytest.raises(ValueError):
        ledger.transfer_utxo("UTXO-HEALTH-103", "M-HEALTH-DEL", amount_paise=float("nan"))
    from cbdcguard.policy_vm import PBMPolicy as _P
    with pytest.raises(ValueError):  # would re-scope every UTXO bound to PBM-AGRI-01
        ledger.register_policy(_P(policy_id="PBM-AGRI-01", name="anything goes"))


def test_api_key_and_input_limits(monkeypatch) -> None:
    import importlib
    import json

    import cbdcguard.api as api

    monkeypatch.setenv("CBDCGUARD_API_KEYS", json.dumps({"s3cret": {"user": "t", "role": "admin"}}))
    api = importlib.reload(api)
    client = TestClient(api.app)
    assert client.post("/reset").status_code == 401
    assert client.post("/cbdc/mint", json={"owner_id": "X", "amount": 1e6}).status_code == 401
    assert client.get("/healthz").status_code == 200
    hdr = {"X-API-Key": "s3cret"}
    assert client.post("/reset", headers=hdr).status_code == 200
    assert client.post("/cbdc/mint", json={"owner_id": "X", "amount": 1e12}, headers=hdr).status_code == 422
    assert client.post("/cbdc/mint", json={"owner_id": "x" * 65, "amount": 10}, headers=hdr).status_code == 422
    r = client.post("/cbdc/mint", json={"owner_id": "X", "amount": 10, "utxo_id": "UTXO-AGRI-101"}, headers=hdr)
    assert r.status_code == 400  # reused UTXO ID
