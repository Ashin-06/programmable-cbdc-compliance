"""Benchmark suite for Programmable CBDC Policy VM & Offline Double-Spend Identity Recovery."""

from __future__ import annotations

import time
from typing import Any

from cbdcguard.ledger import CBDCLedger, MerchantProfile
from cbdcguard.policy_vm import PBMPolicy


def run_benchmark() -> dict[str, Any]:
    """
    Execute 200 programmable CBDC UTXO transactions + 100 offline transactions (including 25 double-spends).
    Verifies:
      - 100% policy enforcement accuracy across all 200 programmable CBDC transactions
      - 100% secret key recovery rate across all 25 offline double-spend attacks
      - 0% secret key leakage across all 75 honest single-show offline spends
    """
    t0 = time.perf_counter()
    ledger = CBDCLedger()

    # Register benchmark merchants covering valid and invalid MCCs, regions, and verification states
    ledger.register_merchant(
        MerchantProfile("M-VALID-AGRI", "Krishi Seeds & Fertilizers", 5261, "Agri Inputs", "IN-MH", True)
    )
    ledger.register_merchant(
        MerchantProfile("M-VALID-FOOD", "Sahakari Grocery Mart", 5411, "Grocery", "IN-KA", True)
    )
    ledger.register_merchant(
        MerchantProfile("M-VALID-HEALTH", "District Civil Hospital", 8062, "Hospital", "IN-DL", True)
    )
    ledger.register_merchant(
        MerchantProfile("M-GAMBLING", "Jackpot Betting Terminal", 7995, "Gambling", "IN-MH", True)
    )
    ledger.register_merchant(
        MerchantProfile("M-ATM-CASHOUT", "Cash Dispenser Kiosk", 6011, "ATM Cash-Out", "IN-MH", True)
    )
    ledger.register_merchant(
        MerchantProfile("M-OUT-OF-REGION", "Assam Agri Depot", 5261, "Agri Inputs", "IN-AS", True)
    )
    ledger.register_merchant(
        MerchantProfile("M-UNVERIFIED", "Unlicensed Seed Stall", 5261, "Agri Inputs", "IN-MH", False)
    )

    expiring_policy = PBMPolicy(
        policy_id="PBM-BENCH-EXP",
        name="Time-Bound Relief Voucher",
        sponsor_id="MINISTRY-FINANCE",
        allowed_mccs={5261, 5191},
        blocked_mccs={7995, 6011},
        allowed_regions={"IN-MH", "IN-KA"},
        max_tx_amount=10000.0,
        expires_at=1_700_000_000,
        unwrap_on_settlement=True,
        require_verified_merchant=True,
    )
    ledger.register_policy(expiring_policy)

    total_programmable = 200
    correct_enforcements = 0
    valid_approved = 0
    violations_blocked = 0
    unwrapped_count = 0
    swept_expired_count = 0
    violation_breakdown: dict[str, int] = {}

    for i in range(total_programmable):
        bucket = i % 8
        utxo_id = f"BENCH-UTXO-{i:03d}"

        if bucket in (0, 1):
            # Valid Agri Subsidy spend -> should approve & unwrap to PBM-GENERAL
            ledger.mint_utxo(f"USER-{i}", 5000.0, "PBM-AGRI-01", utxo_id=utxo_id)
            res = ledger.transfer_utxo(utxo_id, "M-VALID-AGRI", amount=5000.0, timestamp=1_760_000_000)
            expected_allowed = True
            expected_code = None
        elif bucket == 2:
            # Valid Food Voucher spend -> should approve & unwrap to PBM-GENERAL
            ledger.mint_utxo(f"USER-{i}", 2500.0, "PBM-FOOD-02", utxo_id=utxo_id)
            res = ledger.transfer_utxo(utxo_id, "M-VALID-FOOD", amount=2500.0, timestamp=1_760_000_000)
            expected_allowed = True
            expected_code = None
        elif bucket == 3:
            # Blocked MCC (7995 gambling) -> should block with ERR_MCC_BLOCKED
            ledger.mint_utxo(f"USER-{i}", 5000.0, "PBM-AGRI-01", utxo_id=utxo_id)
            res = ledger.transfer_utxo(utxo_id, "M-GAMBLING", amount=1000.0, timestamp=1_760_000_000)
            expected_allowed = False
            expected_code = "ERR_MCC_BLOCKED"
        elif bucket == 4:
            # Disallowed MCC (spending Agri voucher at Hospital MCC 8062) -> ERR_MCC_NOT_ALLOWED
            ledger.mint_utxo(f"USER-{i}", 5000.0, "PBM-AGRI-01", utxo_id=utxo_id)
            res = ledger.transfer_utxo(utxo_id, "M-VALID-HEALTH", amount=2000.0, timestamp=1_760_000_000)
            expected_allowed = False
            expected_code = "ERR_MCC_NOT_ALLOWED"
        elif bucket == 5:
            # Out-of-region geofence violation (IN-AS not in allowed_regions) -> ERR_REGION_OUT_OF_BOUNDS
            ledger.mint_utxo(f"USER-{i}", 5000.0, "PBM-AGRI-01", utxo_id=utxo_id)
            res = ledger.transfer_utxo(utxo_id, "M-OUT-OF-REGION", amount=2000.0, timestamp=1_760_000_000)
            expected_allowed = False
            expected_code = "ERR_REGION_OUT_OF_BOUNDS"
        elif bucket == 6:
            # Exceeds per-transaction ceiling (30,000 > 25,000 max_tx_amount) -> ERR_MAX_TX_AMOUNT_EXCEEDED
            ledger.mint_utxo(f"USER-{i}", 35000.0, "PBM-AGRI-01", utxo_id=utxo_id)
            res = ledger.transfer_utxo(utxo_id, "M-VALID-AGRI", amount=30000.0, timestamp=1_760_000_000)
            expected_allowed = False
            expected_code = "ERR_MAX_TX_AMOUNT_EXCEEDED"
        else:
            # Expired voucher spend attempt -> ERR_UTXO_EXPIRED_CLAWBACK + auto-sweep to sponsor
            ledger.mint_utxo(f"USER-{i}", 4000.0, "PBM-BENCH-EXP", utxo_id=utxo_id)
            res = ledger.transfer_utxo(utxo_id, "M-VALID-AGRI", amount=4000.0, timestamp=1_760_000_000)
            expected_allowed = False
            expected_code = "ERR_UTXO_EXPIRED_CLAWBACK"

        if res.approved == expected_allowed and res.eval_result.violation_code == expected_code:
            correct_enforcements += 1

        if res.approved:
            valid_approved += 1
            if res.unwrapped:
                unwrapped_count += 1
        else:
            violations_blocked += 1
            code = res.eval_result.violation_code or "UNKNOWN"
            violation_breakdown[code] = violation_breakdown.get(code, 0) + 1
            if res.swept_to_sponsor:
                swept_expired_count += 1

    # -------------------------------------------------------------------------
    # Offline NFC Benchmark: 100 transactions (50 honest single-spends + 25 double-spend pairs = 100 packets,
    # plus 25 additional honest single-spends so there are 75 honest coins and 25 double-spent coins)
    # -------------------------------------------------------------------------
    honest_coins_count = 75
    double_spend_attacks_count = 25
    total_offline_transactions = honest_coins_count + double_spend_attacks_count

    expected_attacker_secrets: dict[str, int] = {}

    # 75 Honest single-show offline transactions
    for i in range(honest_coins_count):
        wid = f"W-HONEST-{i:03d}"
        w = ledger.register_offline_wallet(wid, f"Honest Citizen {i}", collateral_balance=10000.0)
        coin = ledger.mint_offline_coin(wid, amount=200.0, coin_id=f"COIN-H-{i:03d}")
        ledger.execute_offline_spend(
            wallet_id=wid,
            coin_id=coin.coin_id,
            merchant_id="M-VALID-AGRI",
            timestamp=1_760_010_000 + i,
            nonce=f"honest-nonce-{i:04d}",
            simulate_double_spend=False,
        )

    # 25 Offline Double-Spend Attacks (each coin spent at two distinct terminals with x1 != x2)
    for j in range(double_spend_attacks_count):
        wid = f"W-ATTACKER-{j:03d}"
        w = ledger.register_offline_wallet(wid, f"Double-Spender {j}", collateral_balance=20000.0)
        expected_attacker_secrets[wid] = w.secret_s
        coin = ledger.mint_offline_coin(wid, amount=1500.0, coin_id=f"COIN-DS-{j:03d}")
        # Spend 1 at Merchant A
        ledger.execute_offline_spend(
            wallet_id=wid,
            coin_id=coin.coin_id,
            merchant_id="M-VALID-AGRI",
            timestamp=1_760_020_000 + j,
            nonce=f"ds-leg1-{j:04d}",
            simulate_double_spend=False,
        )
        # Spend 2 (Cloned / Counter Rollback) at Merchant B
        ledger.execute_offline_spend(
            wallet_id=wid,
            coin_id=coin.coin_id,
            merchant_id="M-VALID-FOOD",
            timestamp=1_760_030_000 + j,
            nonce=f"ds-leg2-{j:04d}",
            simulate_double_spend=True,
        )

    sync_report = ledger.sync_offline_batch()

    # Verify exact secret key recovery on all 25 double-spends and 0% leakage on all 75 honest wallets
    exact_recoveries = 0
    for alert in ledger.double_spend_alerts:
        true_s = expected_attacker_secrets.get(alert.wallet_id)
        if true_s is not None and alert.recovered_secret_s == true_s and alert.verified_against_commitment:
            exact_recoveries += 1

    honest_leaks = 0
    for i in range(honest_coins_count):
        w = ledger.offline_wallets[f"W-HONEST-{i:03d}"]
        if w.recovered_secret_s is not None or w.slashed:
            honest_leaks += 1

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    return {
        "benchmark": "cbdcguard_v1",
        "elapsed_ms": elapsed_ms,
        "programmable_cbdc": {
            "total_transactions": total_programmable,
            "correct_enforcements": correct_enforcements,
            "policy_enforcement_accuracy_pct": round(100.0 * correct_enforcements / total_programmable, 2),
            "valid_approved": valid_approved,
            "violations_blocked": violations_blocked,
            "unwrapped_on_settlement": unwrapped_count,
            "expired_auto_swept": swept_expired_count,
            "violation_breakdown": violation_breakdown,
        },
        "offline_double_spend_guard": {
            "total_offline_scenarios": total_offline_transactions,
            "honest_single_spends": honest_coins_count,
            "double_spend_attacks": double_spend_attacks_count,
            "double_spends_detected": sync_report["double_spends_detected"],
            "exact_secret_keys_recovered": exact_recoveries,
            "double_spend_recovery_rate_pct": round(100.0 * exact_recoveries / double_spend_attacks_count, 2),
            "honest_key_leakage_count": honest_leaks,
            "honest_key_leakage_rate_pct": round(100.0 * honest_leaks / honest_coins_count, 2),
        },
    }
