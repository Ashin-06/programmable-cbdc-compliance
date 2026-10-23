"""CBDC UTXO Ledger, Purpose-Bound Unwrap Engine, Expiry Clawback & Offline Batch Sync."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cbdcguard.offline import (
    DoubleSpendAlert,
    OfflineCoin,
    OfflineSpendPacket,
    OfflineWallet,
    public_point,
    recover_double_spend_secret,
)
from cbdcguard.policy_vm import (
    PBMPolicy,
    PolicyEvalResult,
    PolicyStackVM,
    SpendContext,
    build_preset_policies,
)


@dataclass
class MerchantProfile:
    """Registered merchant or recipient on the e-Rupee network."""

    merchant_id: str
    name: str
    mcc: int
    mcc_label: str
    region: str
    verified: bool = True
    balance_general_erupee: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "merchant_id": self.merchant_id,
            "name": self.name,
            "mcc": self.mcc,
            "mcc_label": self.mcc_label,
            "region": self.region,
            "verified": self.verified,
            "balance_general_erupee": round(self.balance_general_erupee, 2),
        }


@dataclass
class CBDCUTXO:
    """Programmable e-Rupee UTXO carrying a Purpose-Bound Money (PBM) policy lock."""

    utxo_id: str
    owner_id: str
    amount: float
    policy_id: str
    sponsor_id: str
    status: str = "UNSPENT"  # UNSPENT, SPENT, SWEPT_EXPIRED
    unwrapped_from_policy: str | None = None
    created_at: int = 1_750_000_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "utxo_id": self.utxo_id,
            "owner_id": self.owner_id,
            "amount": round(self.amount, 2),
            "policy_id": self.policy_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "unwrapped_from_policy": self.unwrapped_from_policy,
            "created_at": self.created_at,
        }


@dataclass
class TransferOutcome:
    """Outcome of a programmable CBDC transfer attempt."""

    tx_id: str
    utxo_id: str
    sender_id: str
    merchant_id: str
    amount: float
    timestamp: int
    approved: bool
    unwrapped: bool
    swept_to_sponsor: bool
    new_merchant_utxo_id: str | None
    change_utxo_id: str | None
    eval_result: PolicyEvalResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "utxo_id": self.utxo_id,
            "sender_id": self.sender_id,
            "merchant_id": self.merchant_id,
            "amount": round(self.amount, 2),
            "timestamp": self.timestamp,
            "approved": self.approved,
            "unwrapped": self.unwrapped,
            "swept_to_sponsor": self.swept_to_sponsor,
            "new_merchant_utxo_id": self.new_merchant_utxo_id,
            "change_utxo_id": self.change_utxo_id,
            "eval_result": self.eval_result.to_dict(),
        }


class CBDCLedger:
    """Unified Programmable CBDC UTXO & Offline Double-Spend Guard Ledger."""

    def __init__(self, issuer_key: Ed25519PrivateKey | None = None) -> None:
        # The central bank's coin-signing key; offline terminals hold only the public half
        self.issuer_key = issuer_key or Ed25519PrivateKey.generate()
        self.issuer_public_key = self.issuer_key.public_key()
        self.policies: dict[str, PBMPolicy] = build_preset_policies()
        self.merchants: dict[str, MerchantProfile] = {}
        self.utxos: dict[str, CBDCUTXO] = {}
        self.treasury_sweeps: list[dict[str, Any]] = []
        self.transfer_history: list[TransferOutcome] = []

        # Offline NFC state
        self.offline_wallets: dict[str, OfflineWallet] = {}
        self.commitment_to_wallet: dict[bytes, str] = {}
        self.issued_coins: dict[str, OfflineCoin] = {}
        self.pending_offline_packets: list[OfflineSpendPacket] = []
        self.synced_coin_transcripts: dict[str, OfflineSpendPacket] = {}
        self.double_spend_alerts: list[DoubleSpendAlert] = []
        self.honest_offline_settlements: int = 0

    def register_policy(self, policy: PBMPolicy) -> PBMPolicy:
        self.policies[policy.policy_id] = policy
        return policy

    def register_merchant(self, merchant: MerchantProfile) -> MerchantProfile:
        self.merchants[merchant.merchant_id] = merchant
        return merchant

    def mint_utxo(
        self,
        owner_id: str,
        amount: float,
        policy_id: str = "PBM-AGRI-01",
        utxo_id: str | None = None,
        created_at: int = 1_750_000_000,
        custom_policy: PBMPolicy | None = None,
    ) -> CBDCUTXO:
        if custom_policy is not None:
            self.register_policy(custom_policy)
            policy_id = custom_policy.policy_id
        if policy_id not in self.policies:
            raise KeyError(f"Unknown PBM policy_id '{policy_id}'.")
        if amount <= 0:
            raise ValueError("Mint amount must be positive.")

        policy = self.policies[policy_id]
        uid = utxo_id or f"UTXO-{uuid.uuid4().hex[:8].upper()}"
        utxo = CBDCUTXO(
            utxo_id=uid,
            owner_id=owner_id,
            amount=round(float(amount), 2),
            policy_id=policy_id,
            sponsor_id=policy.sponsor_id,
            status="UNSPENT",
            created_at=created_at,
        )
        self.utxos[uid] = utxo
        return utxo

    def transfer_utxo(
        self,
        utxo_id: str,
        merchant_id: str,
        amount: float | None = None,
        timestamp: int = 1_760_000_000,
        sender_kyc_tier: int = 2,
    ) -> TransferOutcome:
        if utxo_id not in self.utxos:
            raise KeyError(f"Unknown UTXO '{utxo_id}'.")
        utxo = self.utxos[utxo_id]
        if utxo.status != "UNSPENT":
            raise ValueError(f"UTXO '{utxo_id}' is not spendable (status={utxo.status}).")
        if merchant_id not in self.merchants:
            raise KeyError(f"Unknown merchant '{merchant_id}'.")

        merchant = self.merchants[merchant_id]
        spend_amount = round(float(amount if amount is not None else utxo.amount), 2)
        if spend_amount <= 0 or spend_amount > utxo.amount + 1e-9:
            raise ValueError(f"Invalid spend amount {spend_amount} for UTXO balance {utxo.amount}.")

        policy = self.policies[utxo.policy_id]
        ctx = SpendContext(
            merchant_id=merchant.merchant_id,
            merchant_mcc=merchant.mcc,
            merchant_region=merchant.region,
            merchant_verified=merchant.verified,
            amount=spend_amount,
            timestamp=timestamp,
            sender_kyc_tier=sender_kyc_tier,
        )

        eval_result = PolicyStackVM.evaluate(policy, ctx)
        tx_id = f"TX-{len(self.transfer_history) + 1:04d}"

        if not eval_result.allowed:
            swept = False
            if eval_result.should_sweep_to_sponsor:
                utxo.status = "SWEPT_EXPIRED"
                swept = True
                self.treasury_sweeps.append(
                    {
                        "utxo_id": utxo.utxo_id,
                        "owner_id": utxo.owner_id,
                        "sponsor_id": utxo.sponsor_id,
                        "amount": utxo.amount,
                        "policy_id": utxo.policy_id,
                        "swept_at": timestamp,
                        "reason": "AUTO_CLAWBACK_ON_EXPIRED_SPEND_ATTEMPT",
                    }
                )
            outcome = TransferOutcome(
                tx_id=tx_id,
                utxo_id=utxo.utxo_id,
                sender_id=utxo.owner_id,
                merchant_id=merchant.merchant_id,
                amount=spend_amount,
                timestamp=timestamp,
                approved=False,
                unwrapped=False,
                swept_to_sponsor=swept,
                new_merchant_utxo_id=None,
                change_utxo_id=None,
                eval_result=eval_result,
            )
            self.transfer_history.append(outcome)
            return outcome

        # Spend approved by PBM Stack VM
        utxo.status = "SPENT"
        target_policy_id = "PBM-GENERAL" if eval_result.should_unwrap else utxo.policy_id
        merchant_utxo_id = f"UTXO-{tx_id}-M"
        merchant_utxo = CBDCUTXO(
            utxo_id=merchant_utxo_id,
            owner_id=merchant.merchant_id,
            amount=spend_amount,
            policy_id=target_policy_id,
            sponsor_id=utxo.sponsor_id,
            status="UNSPENT",
            unwrapped_from_policy=utxo.policy_id if eval_result.should_unwrap else None,
            created_at=timestamp,
        )
        self.utxos[merchant_utxo_id] = merchant_utxo
        if target_policy_id == "PBM-GENERAL":
            merchant.balance_general_erupee += spend_amount

        change_utxo_id: str | None = None
        remainder = round(utxo.amount - spend_amount, 2)
        if remainder > 0:
            change_utxo_id = f"UTXO-{tx_id}-C"
            self.utxos[change_utxo_id] = CBDCUTXO(
                utxo_id=change_utxo_id,
                owner_id=utxo.owner_id,
                amount=remainder,
                policy_id=utxo.policy_id,
                sponsor_id=utxo.sponsor_id,
                status="UNSPENT",
                created_at=timestamp,
            )

        outcome = TransferOutcome(
            tx_id=tx_id,
            utxo_id=utxo.utxo_id,
            sender_id=utxo.owner_id,
            merchant_id=merchant.merchant_id,
            amount=spend_amount,
            timestamp=timestamp,
            approved=True,
            unwrapped=eval_result.should_unwrap,
            swept_to_sponsor=False,
            new_merchant_utxo_id=merchant_utxo_id,
            change_utxo_id=change_utxo_id,
            eval_result=eval_result,
        )
        self.transfer_history.append(outcome)
        return outcome

    def sweep_expired_utxos(self, current_timestamp: int) -> list[dict[str, Any]]:
        """Proactively claw back all unspent UTXOs whose PBM policy has expired."""
        newly_swept: list[dict[str, Any]] = []
        for utxo in self.utxos.values():
            if utxo.status != "UNSPENT":
                continue
            policy = self.policies.get(utxo.policy_id)
            if policy and policy.expires_at is not None and current_timestamp > policy.expires_at:
                utxo.status = "SWEPT_EXPIRED"
                record = {
                    "utxo_id": utxo.utxo_id,
                    "owner_id": utxo.owner_id,
                    "sponsor_id": utxo.sponsor_id,
                    "amount": utxo.amount,
                    "policy_id": utxo.policy_id,
                    "swept_at": current_timestamp,
                    "reason": f"PROACTIVE_EXPIRY_SWEEP (expires_at={policy.expires_at})",
                }
                self.treasury_sweeps.append(record)
                newly_swept.append(record)
        return newly_swept

    # -------------------------------------------------------------------------
    # Offline NFC Single-Show Polynomial Spend & Central Bank Batch Sync
    # -------------------------------------------------------------------------

    def register_offline_wallet(
        self,
        wallet_id: str,
        owner_name: str,
        collateral_balance: float = 25000.0,
        secret_s: int | None = None,
    ) -> OfflineWallet:
        wallet = OfflineWallet.create(
            wallet_id=wallet_id,
            owner_name=owner_name,
            collateral_balance=collateral_balance,
            secret_s=secret_s,
        )
        self.offline_wallets[wallet_id] = wallet
        self.commitment_to_wallet[wallet.commitment_s] = wallet_id
        return wallet

    def mint_offline_coin(
        self,
        wallet_id: str,
        amount: float,
        coin_id: str | None = None,
        blinding_r: int | None = None,
    ) -> OfflineCoin:
        if wallet_id not in self.offline_wallets:
            raise KeyError(f"Unknown offline wallet '{wallet_id}'.")
        if coin_id is not None and coin_id in self.issued_coins:
            raise ValueError(f"Coin ID '{coin_id}' has already been issued.")
        wallet = self.offline_wallets[wallet_id]
        coin = wallet.mint_coin(amount=amount, coin_id=coin_id, blinding_r=blinding_r, issuer_key=self.issuer_key)
        self.issued_coins[coin.coin_id] = coin
        return coin

    def execute_offline_spend(
        self,
        wallet_id: str,
        coin_id: str,
        merchant_id: str,
        timestamp: int = 1_760_005_000,
        nonce: str | None = None,
        simulate_double_spend: bool = False,
    ) -> OfflineSpendPacket:
        """
        Sign an offline spend packet and verify its polynomial commitment proof at the merchant POS terminal.
        Queues the verified packet for later central bank batch synchronization.
        """
        if wallet_id not in self.offline_wallets:
            raise KeyError(f"Unknown offline wallet '{wallet_id}'.")
        wallet = self.offline_wallets[wallet_id]
        actual_nonce = nonce or uuid.uuid4().hex[:10]
        packet = wallet.sign_offline_spend(
            coin_id=coin_id,
            merchant_id=merchant_id,
            timestamp=timestamp,
            nonce=actual_nonce,
            allow_counter_rollback=simulate_double_spend,
        )
        if not packet.verify_terminal_proof(self.issuer_public_key):
            raise ValueError("Offline polynomial commitment verification failed at merchant terminal.")
        self.pending_offline_packets.append(packet)
        return packet

    def sync_offline_batch(self) -> dict[str, Any]:
        """
        Synchronize queued offline merchant packets with the central bank ledger.
        - Honest single spends settle privately (0 bits of secret s leaked).
        - Duplicate coin spends with distinct challenges (x1 != x2) immediately trigger
          Lagrange/slope interpolation s = (y1 - y2)*(x1 - x2)^(-1) mod q, unmasking the
          spender's secret key s and slashing their escrow collateral.
        """
        settled_packets: list[dict[str, Any]] = []
        new_alerts: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []

        while self.pending_offline_packets:
            pkt = self.pending_offline_packets.pop(0)
            if not pkt.verify_terminal_proof(self.issuer_public_key):
                rejected.append({"packet_id": pkt.packet_id, "coin_id": pkt.coin_id, "reason": "INVALID_PROOF_OR_SIGNATURE"})
                continue
            issued = self.issued_coins.get(pkt.coin_id)
            if issued is None or (
                issued.wallet_id, issued.counter, issued.amount_paise, issued.commitment_s, issued.commitment_r
            ) != (pkt.wallet_id, pkt.counter, round(pkt.amount * 100), pkt.commitment_s, pkt.commitment_r):
                # The ledger's own issuance record is the authority, not the packet
                rejected.append({"packet_id": pkt.packet_id, "coin_id": pkt.coin_id, "reason": "NOT_ISSUED_BY_LEDGER"})
                continue

            first = self.synced_coin_transcripts.get(pkt.coin_id)
            if first is not None and first.challenge_x == pkt.challenge_x:
                # The same transcript submitted twice (merchant retry or replay): pay once, no alarm
                rejected.append({"packet_id": pkt.packet_id, "coin_id": pkt.coin_id, "reason": "DUPLICATE_SUBMISSION"})
                continue

            if first is None:
                self.synced_coin_transcripts[pkt.coin_id] = pkt
                self.honest_offline_settlements += 1
                if pkt.merchant_id in self.merchants:
                    self.merchants[pkt.merchant_id].balance_general_erupee += issued.amount
                settled_packets.append(
                    {
                        "packet_id": pkt.packet_id,
                        "coin_id": pkt.coin_id,
                        "merchant_id": pkt.merchant_id,
                        "amount": pkt.amount,
                        "status": "SETTLED_PRIVATE",
                        "identity_exposed": False,
                    }
                )
            else:
                first_pkt = first
                # Double-spend detected! Interpolate the hidden line L(x) = s*x + r mod q
                s_rec, r_rec = recover_double_spend_secret(
                    x1=first_pkt.challenge_x,
                    y1=first_pkt.response_y,
                    x2=pkt.challenge_x,
                    y2=pkt.response_y,
                )
                verified_comm = public_point(s_rec) == pkt.commitment_s
                wallet_id = self.commitment_to_wallet.get(pkt.commitment_s, pkt.wallet_id)
                wallet = self.offline_wallets.get(wallet_id)
                owner_name = wallet.owner_name if wallet else "UNKNOWN"
                slashed_amt = 0.0
                if wallet is not None:
                    penalty = min(wallet.collateral_balance, pkt.amount * 2.0)
                    wallet.collateral_balance = round(wallet.collateral_balance - penalty, 2)
                    wallet.slashed = True
                    wallet.slashed_amount = round(wallet.slashed_amount + penalty, 2)
                    wallet.recovered_secret_s = s_rec
                    slashed_amt = penalty

                alert = DoubleSpendAlert(
                    coin_id=pkt.coin_id,
                    wallet_id=wallet_id,
                    owner_name=owner_name,
                    counter=pkt.counter,
                    amount_per_spend=pkt.amount,
                    merchant_1=first_pkt.merchant_id,
                    merchant_2=pkt.merchant_id,
                    x1=first_pkt.challenge_x,
                    y1=first_pkt.response_y,
                    x2=pkt.challenge_x,
                    y2=pkt.response_y,
                    recovered_secret_s=s_rec,
                    recovered_blinding_r=r_rec,
                    commitment_s=pkt.commitment_s,
                    verified_against_commitment=verified_comm,
                    slashed_collateral=slashed_amt,
                )
                self.double_spend_alerts.append(alert)
                new_alerts.append(alert.to_dict())

        return {
            "settled_count": len(settled_packets),
            "double_spends_detected": len(new_alerts),
            "rejected_count": len(rejected),
            "settled_packets": settled_packets,
            "double_spend_alerts": new_alerts,
            "rejected_packets": rejected,
            "total_double_spend_alerts": len(self.double_spend_alerts),
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "policies": [p.to_dict() for p in self.policies.values()],
            "merchants": [m.to_dict() for m in self.merchants.values()],
            "utxos": [u.to_dict() for u in self.utxos.values()],
            "transfer_history": [t.to_dict() for t in self.transfer_history[-25:]],
            "treasury_sweeps": self.treasury_sweeps,
            "offline_wallets": [w.to_public_dict() for w in self.offline_wallets.values()],
            "pending_offline_packets": [p.to_dict() for p in self.pending_offline_packets],
            "double_spend_alerts": [a.to_dict() for a in self.double_spend_alerts],
            "metrics": {
                "total_utxos": len(self.utxos),
                "unspent_utxos": sum(1 for u in self.utxos.values() if u.status == "UNSPENT"),
                "total_transfers": len(self.transfer_history),
                "approved_transfers": sum(1 for t in self.transfer_history if t.approved),
                "blocked_transfers": sum(1 for t in self.transfer_history if not t.approved),
                "swept_utxos": len(self.treasury_sweeps),
                "pending_offline_count": len(self.pending_offline_packets),
                "double_spend_alerts_count": len(self.double_spend_alerts),
            },
        }


def build_demo_ledger() -> CBDCLedger:
    """Create a pre-populated Indian e-Rupee (e₹) Programmable CBDC & Offline NFC Ledger."""
    ledger = CBDCLedger()

    # Register realistic merchants across MCCs and Indian states
    merchants = [
        MerchantProfile(
            merchant_id="M-AGRI-PUNE",
            name="Sahyadri Krishi Kendra (Seeds & Fertilizer)",
            mcc=5261,
            mcc_label="5261 - Agricultural Seeds & Fertilizers",
            region="IN-MH",
            verified=True,
        ),
        MerchantProfile(
            merchant_id="M-AGRI-BLR",
            name="Kaveri Agro Inputs Cooperative",
            mcc=5191,
            mcc_label="5191 - Farm Supplies & Fertilizers",
            region="IN-KA",
            verified=True,
        ),
        MerchantProfile(
            merchant_id="M-FOOD-MUM",
            name="ApnaBazar Sahakari Bhandar (Grocery)",
            mcc=5411,
            mcc_label="5411 - Grocery Stores & Supermarkets",
            region="IN-MH",
            verified=True,
        ),
        MerchantProfile(
            merchant_id="M-HEALTH-DEL",
            name="Indraprastha Care Hospital",
            mcc=8062,
            mcc_label="8062 - Accredited Hospitals",
            region="IN-DL",
            verified=True,
        ),
        MerchantProfile(
            merchant_id="M-CASINO-GOA",
            name="Offshore Royal Jackpot & Betting Club",
            mcc=7995,
            mcc_label="7995 - Gambling & Betting (Blocked)",
            region="IN-GA",
            verified=True,
        ),
        MerchantProfile(
            merchant_id="M-ATM-MUM",
            name="Instant Cash-Out Kiosk ATM",
            mcc=6011,
            mcc_label="6011 - Automated Cash Disbursements (Blocked)",
            region="IN-MH",
            verified=True,
        ),
        MerchantProfile(
            merchant_id="M-UNVERIFIED-AGRI",
            name="Unregistered Roadside Seed Broker",
            mcc=5261,
            mcc_label="5261 - Agricultural Seeds (Unverified KYC)",
            region="IN-MH",
            verified=False,
        ),
    ]
    for m in merchants:
        ledger.register_merchant(m)

    # Seed programmable CBDC UTXOs
    ledger.mint_utxo(
        owner_id="FARMER-RAMESH-MH",
        amount=12000.0,
        policy_id="PBM-AGRI-01",
        utxo_id="UTXO-AGRI-101",
    )
    ledger.mint_utxo(
        owner_id="BENEFICIARY-PRIYA-MH",
        amount=3500.0,
        policy_id="PBM-FOOD-02",
        utxo_id="UTXO-FOOD-102",
    )
    ledger.mint_utxo(
        owner_id="PATIENT-ANIL-DL",
        amount=45000.0,
        policy_id="PBM-HEALTH-03",
        utxo_id="UTXO-HEALTH-103",
    )
    # Seed an expiring subsidy UTXO for testing expiry clawback
    expired_policy = PBMPolicy(
        policy_id="PBM-DROUGHT-EXP",
        name="Kharif 2025 Drought Relief Voucher (Expired)",
        description="Time-bound relief voucher with expiry timestamp 1700000000; auto-sweeps back to Ministry of Agriculture upon expiry.",
        sponsor_id="MINISTRY-AGRI-TREASURY",
        allowed_mccs={5191, 5261},
        blocked_mccs={7995, 6011},
        allowed_regions={"IN-MH", "IN-KA"},
        max_tx_amount=15000.0,
        expires_at=1_700_000_000,
        unwrap_on_settlement=True,
        require_verified_merchant=True,
    )
    ledger.mint_utxo(
        owner_id="FARMER-SURESH-KA",
        amount=8000.0,
        custom_policy=expired_policy,
        utxo_id="UTXO-EXP-104",
        created_at=1_690_000_000,
    )

    # Seed offline NFC wallets & coins
    w1 = ledger.register_offline_wallet(
        wallet_id="WALLET-NFC-01",
        owner_name="Kavita Deshmukh (Honest Rural NFC User)",
        collateral_balance=15000.0,
    )
    ledger.mint_offline_coin(wallet_id=w1.wallet_id, amount=500.0, coin_id="OFFCOIN-NFC01-001")
    ledger.mint_offline_coin(wallet_id=w1.wallet_id, amount=1000.0, coin_id="OFFCOIN-NFC01-002")

    w2 = ledger.register_offline_wallet(
        wallet_id="WALLET-NFC-02",
        owner_name="Vikram Rogue (Cloned Secure Element Attacker)",
        collateral_balance=20000.0,
    )
    ledger.mint_offline_coin(wallet_id=w2.wallet_id, amount=2000.0, coin_id="OFFCOIN-NFC02-001")

    return ledger
