"""CBDC UTXO ledger, purpose-bound unwrap engine, expiry clawback and offline batch sync.

State lives in a database (db.py): SQLite by default, Postgres in production. Money is integer
paise throughout. Each operation is one transaction under a per-process lock, and the spend
guards are in SQL as well (a UTXO leaves UNSPENT once, a coin is paid once, a pending packet is
claimed once), so replicas sharing a database cannot double-pay.

This is a simulation: the ledger also plays every offline wallet's secure element, so it keeps
each wallet's secret s and each coin's blinding r. They are sealed with AES-256-GCM under the
wallet key (CBDCGUARD_WALLET_KEY). A real ledger would never hold them.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import secrets
import threading
from typing import Any, Callable
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from cbdcguard import db
from cbdcguard.money import rupees
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

LIST_LIMIT = 500  # Snapshot lists are capped; page through the tables if a real UI needs more
_NEXT_SEQ = {  # constant SQL per table, so nothing is formatted into a query
    "transfers": "SELECT MAX(seq) FROM transfers",
    "offline_packets": "SELECT MAX(seq) FROM offline_packets",
    "double_spend_alerts": "SELECT MAX(seq) FROM double_spend_alerts",
}
_TABLES = ("policies", "merchants", "utxos", "transfers", "sweeps", "offline_wallets", "offline_coins",
           "offline_packets", "settled_coins", "double_spend_alerts")


class _Conflict(Exception):
    """Another replica changed a row this transaction read; run the operation again."""


def _paise(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{what} must be a positive whole number of paise.")
    return value


@dataclass
class MerchantProfile:
    """Registered merchant or recipient on the e-Rupee network."""

    merchant_id: str
    name: str
    mcc: int
    mcc_label: str
    region: str
    verified: bool = True
    balance_paise: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "merchant_id": self.merchant_id,
            "name": self.name,
            "mcc": self.mcc,
            "mcc_label": self.mcc_label,
            "region": self.region,
            "verified": self.verified,
            "balance_general_erupee": rupees(self.balance_paise),
            "balance_paise": self.balance_paise,
        }


@dataclass
class CBDCUTXO:
    """Programmable e-Rupee UTXO carrying a Purpose-Bound Money (PBM) policy lock."""

    utxo_id: str
    owner_id: str
    amount_paise: int
    policy_id: str
    sponsor_id: str
    status: str = "UNSPENT"  # UNSPENT, SPENT, SWEPT_EXPIRED
    unwrapped_from_policy: str | None = None
    created_at: int = 1_750_000_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "utxo_id": self.utxo_id,
            "owner_id": self.owner_id,
            "amount": rupees(self.amount_paise),
            "amount_paise": self.amount_paise,
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
    amount_paise: int
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
            "amount": rupees(self.amount_paise),
            "amount_paise": self.amount_paise,
            "timestamp": self.timestamp,
            "approved": self.approved,
            "unwrapped": self.unwrapped,
            "swept_to_sponsor": self.swept_to_sponsor,
            "new_merchant_utxo_id": self.new_merchant_utxo_id,
            "change_utxo_id": self.change_utxo_id,
            "eval_result": self.eval_result.to_dict(),
        }


def _merchant_from(r: Any) -> MerchantProfile:
    return MerchantProfile(r.merchant_id, r.name, r.mcc, r.mcc_label, r.region, bool(r.verified), r.balance_paise)


def _utxo_from(r: Any) -> CBDCUTXO:
    return CBDCUTXO(r.utxo_id, r.owner_id, r.amount_paise, r.policy_id, r.sponsor_id, r.status,
                    r.unwrapped_from_policy, r.created_at)


class CBDCLedger:
    """Programmable CBDC UTXO ledger and offline double-spend guard, backed by a database."""

    def __init__(
        self,
        engine: Engine | None = None,
        issuer_key: Ed25519PrivateKey | None = None,
        wallet_key: bytes | None = None,
        previous_issuer_keys: tuple[Ed25519PrivateKey, ...] = (),
        previous_wallet_keys: tuple[bytes, ...] = (),
    ) -> None:
        self.db = engine or db.connect("sqlite://")
        # The central bank's coin-signing key; offline terminals hold only the public half(s)
        self.issuer_key = issuer_key or Ed25519PrivateKey.generate()
        self.issuer_public_key = self.issuer_key.public_key()
        self._issuer_publics = [self.issuer_public_key, *(k.public_key() for k in previous_issuer_keys)]
        self._aead = AESGCM(wallet_key or AESGCM.generate_key(bit_length=256))
        self._old_aeads = [AESGCM(k) for k in previous_wallet_keys]  # still readable while rotating
        self._lock = threading.Lock()  # Per process; other replicas are stopped by the SQL guards
        self._tx(self._seed_policies)

    # --- plumbing ------------------------------------------------------------------------

    def _tx(self, fn: Callable[[Connection], Any]) -> Any:
        """Run fn in one transaction under the process lock; again if another replica won a race."""
        for attempt in range(3):
            try:
                with self._lock, self.db.begin() as c:
                    return fn(c)
            except (IntegrityError, _Conflict):
                if attempt == 2:
                    raise
        raise AssertionError("unreachable")

    def _read(self, fn: Callable[[Connection], Any]) -> Any:
        with self._lock, self.db.connect() as c:
            return fn(c)

    @staticmethod
    def _next_seq(c: Connection, table: str) -> int:
        return (c.execute(text(_NEXT_SEQ[table])).scalar() or 0) + 1

    def _seal(self, value: int, aad: str) -> str:
        nonce = secrets.token_bytes(12)
        return base64.b64encode(nonce + self._aead.encrypt(nonce, value.to_bytes(32, "little"), aad.encode())).decode()

    def _unseal(self, sealed: str, aad: str) -> int:
        raw = base64.b64decode(sealed)
        for aead in (self._aead, *self._old_aeads):
            try:
                return int.from_bytes(aead.decrypt(raw[:12], raw[12:], aad.encode()), "little")
            except InvalidTag:
                continue
        raise ValueError("cannot unseal a wallet secret: wrong wallet key, or the key it was sealed with was rotated out")

    def wipe(self) -> None:
        """Delete every row (demo reset); the preset policies are put back."""
        def run(c: Connection) -> None:
            for t in _TABLES:  # table names are the constants above, never input
                c.execute(text("DELETE FROM " + t))  # nosec B608
            self._seed_policies(c)

        self._tx(run)

    def is_empty(self) -> bool:
        return self._read(lambda c: c.execute(text("SELECT COUNT(*) FROM merchants")).scalar() == 0)

    # --- policies and merchants ------------------------------------------------------------

    def _seed_policies(self, c: Connection) -> None:
        # Insert-only: once stored, the database copy of a policy is the one that counts
        for p in build_preset_policies().values():
            if self._policy(c, p.policy_id) is None:
                self._insert_policy(c, p)

    @staticmethod
    def _policy(c: Connection, policy_id: str) -> PBMPolicy | None:
        row = c.execute(text("SELECT doc FROM policies WHERE policy_id = :p"), {"p": policy_id}).first()
        return PBMPolicy.from_dict(json.loads(row.doc)) if row else None

    @staticmethod
    def _insert_policy(c: Connection, policy: PBMPolicy) -> None:
        c.execute(text("INSERT INTO policies (policy_id, expires_at, doc) VALUES (:p, :e, :d)"),
                  {"p": policy.policy_id, "e": policy.expires_at, "d": json.dumps(policy.to_dict())})

    def _put_policy(self, c: Connection, policy: PBMPolicy) -> None:
        existing = self._policy(c, policy.policy_id)
        if existing is None:
            self._insert_policy(c, policy)
        elif existing.to_dict() != policy.to_dict():
            # Replacing a policy would silently re-scope every UTXO already bound to it
            raise ValueError(f"Policy ID '{policy.policy_id}' is already registered.")

    def register_policy(self, policy: PBMPolicy) -> PBMPolicy:
        self._tx(lambda c: self._put_policy(c, policy))
        return policy

    def policy(self, policy_id: str) -> PBMPolicy | None:
        return self._read(lambda c: self._policy(c, policy_id))

    def register_merchant(self, merchant: MerchantProfile) -> MerchantProfile:
        def run(c: Connection) -> None:
            if c.execute(text("SELECT 1 FROM merchants WHERE merchant_id = :m"), {"m": merchant.merchant_id}).first():
                raise ValueError(f"Merchant '{merchant.merchant_id}' is already registered.")
            c.execute(text("INSERT INTO merchants (merchant_id, name, mcc, mcc_label, region, verified, balance_paise) "
                           "VALUES (:id, :n, :mcc, :l, :r, :v, :b)"),
                      {"id": merchant.merchant_id, "n": merchant.name, "mcc": merchant.mcc, "l": merchant.mcc_label,
                       "r": merchant.region, "v": int(merchant.verified), "b": merchant.balance_paise})

        self._tx(run)
        return merchant

    @staticmethod
    def _merchant(c: Connection, merchant_id: str) -> MerchantProfile | None:
        row = c.execute(text("SELECT * FROM merchants WHERE merchant_id = :m"), {"m": merchant_id}).first()
        return _merchant_from(row) if row else None

    def merchant(self, merchant_id: str) -> MerchantProfile | None:
        return self._read(lambda c: self._merchant(c, merchant_id))

    # --- programmable UTXOs ----------------------------------------------------------------

    @staticmethod
    def _utxo(c: Connection, utxo_id: str) -> CBDCUTXO | None:
        row = c.execute(text("SELECT * FROM utxos WHERE utxo_id = :u"), {"u": utxo_id}).first()
        return _utxo_from(row) if row else None

    @staticmethod
    def _insert_utxo(c: Connection, u: CBDCUTXO) -> None:
        c.execute(text("INSERT INTO utxos (utxo_id, owner_id, amount_paise, policy_id, sponsor_id, status, "
                       "unwrapped_from_policy, created_at) VALUES (:id, :o, :a, :p, :s, :st, :uw, :t)"),
                  {"id": u.utxo_id, "o": u.owner_id, "a": u.amount_paise, "p": u.policy_id, "s": u.sponsor_id,
                   "st": u.status, "uw": u.unwrapped_from_policy, "t": u.created_at})

    def utxo(self, utxo_id: str) -> CBDCUTXO | None:
        return self._read(lambda c: self._utxo(c, utxo_id))

    def mint_utxo(
        self,
        owner_id: str,
        amount_paise: int,
        policy_id: str = "PBM-AGRI-01",
        utxo_id: str | None = None,
        created_at: int = 1_750_000_000,
        custom_policy: PBMPolicy | None = None,
    ) -> CBDCUTXO:
        _paise(amount_paise, "Mint amount")
        uid = utxo_id or f"UTXO-{uuid.uuid4().hex[:8].upper()}"

        def run(c: Connection) -> CBDCUTXO:
            pid = policy_id
            if custom_policy is not None:
                self._put_policy(c, custom_policy)
                pid = custom_policy.policy_id
            policy = self._policy(c, pid)
            if policy is None:
                raise KeyError(f"Unknown PBM policy_id '{pid}'.")
            if self._utxo(c, uid) is not None:
                # Overwriting would turn a SPENT or SWEPT UTXO back into a fresh UNSPENT one
                raise ValueError(f"UTXO ID '{uid}' already exists.")
            utxo = CBDCUTXO(uid, owner_id, amount_paise, pid, policy.sponsor_id, "UNSPENT", None, created_at)
            self._insert_utxo(c, utxo)
            return utxo

        return self._tx(run)

    @staticmethod
    def _sweep(c: Connection, u: CBDCUTXO, timestamp: int, reason: str) -> dict[str, Any] | None:
        if c.execute(text("UPDATE utxos SET status = 'SWEPT_EXPIRED' WHERE utxo_id = :u AND status = 'UNSPENT'"),
                     {"u": u.utxo_id}).rowcount != 1:
            return None
        record = {
            "utxo_id": u.utxo_id,
            "owner_id": u.owner_id,
            "sponsor_id": u.sponsor_id,
            "amount": rupees(u.amount_paise),
            "amount_paise": u.amount_paise,
            "policy_id": u.policy_id,
            "swept_at": timestamp,
            "reason": reason,
        }
        c.execute(text("INSERT INTO sweeps (utxo_id, swept_at, doc) VALUES (:u, :t, :d)"),
                  {"u": u.utxo_id, "t": timestamp, "d": json.dumps(record)})
        return record

    def transfer_utxo(
        self,
        utxo_id: str,
        merchant_id: str,
        amount_paise: int | None = None,
        timestamp: int = 1_760_000_000,
        sender_kyc_tier: int = 2,
    ) -> TransferOutcome:
        def run(c: Connection) -> TransferOutcome:
            utxo = self._utxo(c, utxo_id)
            if utxo is None:
                raise KeyError(f"Unknown UTXO '{utxo_id}'.")
            if utxo.status != "UNSPENT":
                raise ValueError(f"UTXO '{utxo_id}' is not spendable (status={utxo.status}).")
            merchant = self._merchant(c, merchant_id)
            if merchant is None:
                raise KeyError(f"Unknown merchant '{merchant_id}'.")
            spend = utxo.amount_paise if amount_paise is None else _paise(amount_paise, "Spend amount")
            if spend > utxo.amount_paise:
                raise ValueError(f"Spend of {rupees(spend)} exceeds UTXO balance {rupees(utxo.amount_paise)}.")

            policy = self._policy(c, utxo.policy_id)
            ctx = SpendContext(
                merchant_id=merchant.merchant_id,
                merchant_mcc=merchant.mcc,
                merchant_region=merchant.region,
                merchant_verified=merchant.verified,
                amount_paise=spend,
                timestamp=timestamp,
                sender_kyc_tier=sender_kyc_tier,
            )
            eval_result = PolicyStackVM.evaluate(policy, ctx)
            seq = self._next_seq(c, "transfers")
            tx_id = f"TX-{seq:04d}"
            outcome = TransferOutcome(tx_id, utxo.utxo_id, utxo.owner_id, merchant.merchant_id, spend, timestamp,
                                      approved=eval_result.allowed, unwrapped=False, swept_to_sponsor=False,
                                      new_merchant_utxo_id=None, change_utxo_id=None, eval_result=eval_result)

            if not eval_result.allowed:
                if eval_result.should_sweep_to_sponsor:
                    outcome.swept_to_sponsor = self._sweep(c, utxo, timestamp, "AUTO_CLAWBACK_ON_EXPIRED_SPEND_ATTEMPT") is not None
            else:
                if c.execute(text("UPDATE utxos SET status = 'SPENT' WHERE utxo_id = :u AND status = 'UNSPENT'"),
                             {"u": utxo.utxo_id}).rowcount != 1:
                    raise _Conflict  # spent by another replica since we read it
                target = "PBM-GENERAL" if eval_result.should_unwrap else utxo.policy_id
                outcome.unwrapped = eval_result.should_unwrap
                outcome.new_merchant_utxo_id = f"UTXO-{tx_id}-M"
                self._insert_utxo(c, CBDCUTXO(outcome.new_merchant_utxo_id, merchant.merchant_id, spend, target,
                                              utxo.sponsor_id, "UNSPENT",
                                              utxo.policy_id if eval_result.should_unwrap else None, timestamp))
                if target == "PBM-GENERAL":
                    c.execute(text("UPDATE merchants SET balance_paise = balance_paise + :a WHERE merchant_id = :m"),
                              {"a": spend, "m": merchant.merchant_id})
                remainder = utxo.amount_paise - spend
                if remainder > 0:
                    outcome.change_utxo_id = f"UTXO-{tx_id}-C"
                    self._insert_utxo(c, CBDCUTXO(outcome.change_utxo_id, utxo.owner_id, remainder, utxo.policy_id,
                                                  utxo.sponsor_id, "UNSPENT", None, timestamp))

            c.execute(text("INSERT INTO transfers (seq, tx_id, approved, doc) VALUES (:s, :t, :a, :d)"),
                      {"s": seq, "t": tx_id, "a": int(outcome.approved), "d": json.dumps(outcome.to_dict())})
            return outcome

        return self._tx(run)

    def sweep_expired_utxos(self, current_timestamp: int) -> list[dict[str, Any]]:
        """Proactively claw back all unspent UTXOs whose PBM policy has expired."""
        def run(c: Connection) -> list[dict[str, Any]]:
            rows = c.execute(text("SELECT u.*, p.expires_at FROM utxos u JOIN policies p ON p.policy_id = u.policy_id "
                                  "WHERE u.status = 'UNSPENT' AND p.expires_at IS NOT NULL AND p.expires_at < :t"),
                             {"t": current_timestamp}).all()
            swept = [self._sweep(c, _utxo_from(r), current_timestamp, f"PROACTIVE_EXPIRY_SWEEP (expires_at={r.expires_at})")
                     for r in rows]
            return [s for s in swept if s is not None]

        return self._tx(run)

    # --- offline coins ---------------------------------------------------------------------

    def _wallet(self, c: Connection, wallet_id: str, with_coins: bool = False, unseal: bool = True) -> OfflineWallet | None:
        """unseal=False loads it for display: secret_s and the coins' blinding_r stay None."""
        r = c.execute(text("SELECT * FROM offline_wallets WHERE wallet_id = :w"), {"w": wallet_id}).first()
        if r is None:
            return None
        wallet = OfflineWallet(
            wallet_id=r.wallet_id,
            owner_name=r.owner_name,
            secret_s=self._unseal(r.sealed_secret, f"wallet|{r.wallet_id}") if unseal else None,
            commitment_s=bytes.fromhex(r.commitment_s),
            collateral_paise=r.collateral_paise,
            monotonic_counter=r.monotonic_counter,
            slashed=bool(r.slashed),
            slashed_paise=r.slashed_paise,
            recovered_secret_s=int(r.recovered_secret_s, 16) if r.recovered_secret_s else None,
        )
        if with_coins:
            for row in c.execute(text("SELECT * FROM offline_coins WHERE wallet_id = :w ORDER BY counter"), {"w": wallet_id}):
                wallet.coins[row.coin_id] = self._coin_from(row, unseal)
        return wallet

    def _coin_from(self, r: Any, unseal: bool = True) -> OfflineCoin:
        return OfflineCoin(
            coin_id=r.coin_id,
            wallet_id=r.wallet_id,
            counter=r.counter,
            amount_paise=r.amount_paise,
            blinding_r=self._unseal(r.sealed_blinding, f"coin|{r.coin_id}") if unseal else None,
            commitment_s=bytes.fromhex(r.commitment_s),
            commitment_r=bytes.fromhex(r.commitment_r),
            issuer_signature=bytes.fromhex(r.issuer_signature),
            spent_count=r.spent_count,
        )

    def wallet(self, wallet_id: str) -> OfflineWallet | None:
        """The wallet with its coins, secrets unsealed (the simulated secure element's view)."""
        return self._read(lambda c: self._wallet(c, wallet_id, with_coins=True))

    def register_offline_wallet(
        self,
        wallet_id: str,
        owner_name: str,
        collateral_paise: int = 2_500_000,
        secret_s: int | None = None,
    ) -> OfflineWallet:
        if isinstance(collateral_paise, bool) or not isinstance(collateral_paise, int) or collateral_paise < 0:
            raise ValueError("Collateral must be a whole number of paise, zero or more.")
        wallet = OfflineWallet.create(wallet_id, owner_name, collateral_paise=collateral_paise, secret_s=secret_s)

        def run(c: Connection) -> None:
            if c.execute(text("SELECT 1 FROM offline_wallets WHERE wallet_id = :w"), {"w": wallet_id}).first():
                raise ValueError(f"Offline wallet '{wallet_id}' is already registered.")
            c.execute(text("INSERT INTO offline_wallets (wallet_id, owner_name, sealed_secret, commitment_s, collateral_paise, "
                           "monotonic_counter, slashed, slashed_paise, recovered_secret_s) "
                           "VALUES (:w, :o, :s, :cs, :cp, 0, 0, 0, NULL)"),
                      {"w": wallet_id, "o": owner_name, "s": self._seal(wallet.secret_s, f"wallet|{wallet_id}"),
                       "cs": wallet.commitment_s.hex(), "cp": collateral_paise})

        self._tx(run)
        return wallet

    def mint_offline_coin(
        self,
        wallet_id: str,
        amount_paise: int,
        coin_id: str | None = None,
        blinding_r: int | None = None,
    ) -> OfflineCoin:
        def run(c: Connection) -> OfflineCoin:
            wallet = self._wallet(c, wallet_id)
            if wallet is None:
                raise KeyError(f"Unknown offline wallet '{wallet_id}'.")
            cid = coin_id or f"OFFCOIN-{wallet_id}-{wallet.monotonic_counter + 1:03d}"
            if c.execute(text("SELECT 1 FROM offline_coins WHERE coin_id = :c"), {"c": cid}).first():
                raise ValueError(f"Coin ID '{cid}' has already been issued.")
            coin = wallet.mint_coin(amount_paise=amount_paise, coin_id=cid, blinding_r=blinding_r, issuer_key=self.issuer_key)
            c.execute(text("UPDATE offline_wallets SET monotonic_counter = :n WHERE wallet_id = :w"),
                      {"n": wallet.monotonic_counter, "w": wallet_id})
            c.execute(text("INSERT INTO offline_coins (coin_id, wallet_id, counter, amount_paise, sealed_blinding, commitment_s, "
                           "commitment_r, issuer_signature, spent_count) VALUES (:c, :w, :n, :a, :b, :s, :r, :sig, 0)"),
                      {"c": coin.coin_id, "w": wallet_id, "n": coin.counter, "a": coin.amount_paise,
                       "b": self._seal(coin.blinding_r, f"coin|{coin.coin_id}"), "s": coin.commitment_s.hex(),
                       "r": coin.commitment_r.hex(), "sig": coin.issuer_signature.hex()})
            return coin

        return self._tx(run)

    def _queue(self, c: Connection, packet: OfflineSpendPacket) -> None:
        c.execute(text("INSERT INTO offline_packets (seq, packet_id, coin_id, status, reason, doc) "
                       "VALUES (:s, :p, :c, 'PENDING', NULL, :d)"),
                  {"s": self._next_seq(c, "offline_packets"), "p": packet.packet_id, "c": packet.coin_id,
                   "d": json.dumps(packet.to_dict())})

    def queue_packet(self, packet: OfflineSpendPacket) -> None:
        """A merchant terminal uploads a packet it accepted offline; sync checks it."""
        self._tx(lambda c: self._queue(c, packet))

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
        The wallet answers the terminal's challenge, the terminal checks it offline, and the packet
        is queued for the central bank's batch sync.
        """
        actual_nonce = nonce or uuid.uuid4().hex[:10]

        def run(c: Connection) -> OfflineSpendPacket:
            wallet = self._wallet(c, wallet_id)
            if wallet is None:
                raise KeyError(f"Unknown offline wallet '{wallet_id}'.")
            row = c.execute(text("SELECT * FROM offline_coins WHERE coin_id = :c AND wallet_id = :w"),
                            {"c": coin_id, "w": wallet_id}).first()
            if row is None:
                raise KeyError(f"Unknown offline coin '{coin_id}' in wallet '{wallet_id}'.")
            coin = self._coin_from(row)
            wallet.coins[coin.coin_id] = coin
            packet = wallet.sign_offline_spend(
                coin_id=coin_id,
                merchant_id=merchant_id,
                timestamp=timestamp,
                nonce=actual_nonce,
                allow_counter_rollback=simulate_double_spend,
            )
            if not any(packet.verify_terminal_proof(pk) for pk in self._issuer_publics):
                raise ValueError("Offline polynomial commitment verification failed at merchant terminal.")
            if c.execute(text("UPDATE offline_coins SET spent_count = :n WHERE coin_id = :c AND spent_count = :old"),
                         {"n": coin.spent_count, "c": coin_id, "old": row.spent_count}).rowcount != 1:
                raise _Conflict
            self._queue(c, packet)
            return packet

        return self._tx(run)

    def _sync_one(self, c: Connection) -> tuple[str, dict[str, Any] | None] | None:
        """Settle the oldest pending packet. None when nothing is pending."""
        row = c.execute(text("SELECT seq, doc FROM offline_packets WHERE status = 'PENDING' ORDER BY seq LIMIT 1")).first()
        if row is None:
            return None
        if c.execute(text("UPDATE offline_packets SET status = 'CLAIMED' WHERE seq = :s AND status = 'PENDING'"),
                     {"s": row.seq}).rowcount != 1:
            return "skip", None  # another replica is settling it
        pkt = OfflineSpendPacket.from_dict(json.loads(row.doc))

        def done(status: str, kind: str, item: dict[str, Any], reason: str | None = None) -> tuple[str, dict[str, Any]]:
            c.execute(text("UPDATE offline_packets SET status = :st, reason = :r WHERE seq = :s"),
                      {"st": status, "r": reason, "s": row.seq})
            return kind, item

        def reject(status: str, reason: str) -> tuple[str, dict[str, Any]]:
            return done(status, "rejected", {"packet_id": pkt.packet_id, "coin_id": pkt.coin_id, "reason": reason}, reason)

        if not any(pkt.verify_terminal_proof(pk) for pk in self._issuer_publics):
            return reject("REJECTED", "INVALID_PROOF_OR_SIGNATURE")
        issued = c.execute(text("SELECT wallet_id, counter, amount_paise, commitment_s, commitment_r FROM offline_coins "
                                "WHERE coin_id = :c"), {"c": pkt.coin_id}).first()
        if issued is None or tuple(issued) != (pkt.wallet_id, pkt.counter, pkt.amount_paise, pkt.commitment_s.hex(),
                                               pkt.commitment_r.hex()):
            # The ledger's own issuance record is the authority, not the packet
            return reject("REJECTED", "NOT_ISSUED_BY_LEDGER")

        first_row = c.execute(text("SELECT p.doc FROM settled_coins s JOIN offline_packets p ON p.seq = s.packet_seq "
                                   "WHERE s.coin_id = :c"), {"c": pkt.coin_id}).first()
        if first_row is None:
            c.execute(text("INSERT INTO settled_coins (coin_id, packet_seq) VALUES (:c, :s)"), {"c": pkt.coin_id, "s": row.seq})
            c.execute(text("UPDATE merchants SET balance_paise = balance_paise + :a WHERE merchant_id = :m"),
                      {"a": issued.amount_paise, "m": pkt.merchant_id})
            return done("SETTLED", "settled", {
                "packet_id": pkt.packet_id,
                "coin_id": pkt.coin_id,
                "merchant_id": pkt.merchant_id,
                "amount": rupees(issued.amount_paise),
                "amount_paise": issued.amount_paise,
                "status": "SETTLED_PRIVATE",
                "identity_exposed": False,
            })

        first = OfflineSpendPacket.from_dict(json.loads(first_row.doc))
        if first.challenge_x == pkt.challenge_x:
            # The same transcript submitted twice (merchant retry or replay): pay once, no alarm
            return reject("DUPLICATE", "DUPLICATE_SUBMISSION")

        # Double spend: two points on the hidden line L(x) = s*x + r mod L give s
        s_rec, r_rec = recover_double_spend_secret(x1=first.challenge_x, y1=first.response_y,
                                                   x2=pkt.challenge_x, y2=pkt.response_y)
        w = c.execute(text("SELECT wallet_id, owner_name, collateral_paise FROM offline_wallets WHERE commitment_s = :s"),
                      {"s": pkt.commitment_s.hex()}).first()
        penalty = 0
        if w is not None:
            penalty = min(w.collateral_paise, pkt.amount_paise * 2)
            if c.execute(text("UPDATE offline_wallets SET collateral_paise = collateral_paise - :p, slashed = 1, "
                              "slashed_paise = slashed_paise + :p, recovered_secret_s = :s "
                              "WHERE wallet_id = :w AND collateral_paise = :before"),
                         {"p": penalty, "s": hex(s_rec), "w": w.wallet_id, "before": w.collateral_paise}).rowcount != 1:
                raise _Conflict  # slashed by another replica since we read it
        alert = DoubleSpendAlert(
            coin_id=pkt.coin_id,
            wallet_id=w.wallet_id if w else pkt.wallet_id,
            owner_name=w.owner_name if w else "UNKNOWN",
            counter=pkt.counter,
            amount_per_spend_paise=pkt.amount_paise,
            merchant_1=first.merchant_id,
            merchant_2=pkt.merchant_id,
            x1=first.challenge_x,
            y1=first.response_y,
            x2=pkt.challenge_x,
            y2=pkt.response_y,
            recovered_secret_s=s_rec,
            recovered_blinding_r=r_rec,
            commitment_s=pkt.commitment_s,
            verified_against_commitment=public_point(s_rec) == pkt.commitment_s,
            slashed_paise=penalty,
        ).to_dict()
        c.execute(text("INSERT INTO double_spend_alerts (seq, coin_id, wallet_id, doc) VALUES (:s, :c, :w, :d)"),
                  {"s": self._next_seq(c, "double_spend_alerts"), "c": pkt.coin_id, "w": alert["wallet_id"],
                   "d": json.dumps(alert)})
        return done("DOUBLE_SPEND", "alert", alert, "DOUBLE_SPEND")

    def sync_offline_batch(self) -> dict[str, Any]:
        """
        Settle every queued offline packet against the ledger.
        - An honest single spend settles; nothing about the wallet's secret s is revealed.
        - Two different answers for one coin give s = (y1 - y2) * (x1 - x2)^(-1) mod L, which
          identifies the double spender and slashes their collateral.
        """
        out: dict[str, list[dict[str, Any]]] = {"settled": [], "alert": [], "rejected": []}
        while (res := self._tx(self._sync_one)) is not None:
            kind, item = res
            if item is not None:
                out[kind].append(item)
        total = self._read(lambda c: c.execute(text("SELECT COUNT(*) FROM double_spend_alerts")).scalar())
        return {
            "settled_count": len(out["settled"]),
            "double_spends_detected": len(out["alert"]),
            "rejected_count": len(out["rejected"]),
            "settled_packets": out["settled"],
            "double_spend_alerts": out["alert"],
            "rejected_packets": out["rejected"],
            "total_double_spend_alerts": total,
        }

    def pending_count(self) -> int:
        return self._read(lambda c: c.execute(text("SELECT COUNT(*) FROM offline_packets WHERE status = 'PENDING'")).scalar())

    def alerts(self) -> list[dict[str, Any]]:
        return self._read(lambda c: [json.loads(r.doc) for r in
                                     c.execute(text("SELECT doc FROM double_spend_alerts ORDER BY seq"))])

    def snapshot(self) -> dict[str, Any]:
        def run(c: Connection) -> dict[str, Any]:
            def docs(sql: str) -> list[dict[str, Any]]:
                return [json.loads(r.doc) for r in c.execute(text(sql), {"n": LIST_LIMIT})]

            def count(sql: str) -> int:
                return c.execute(text(sql)).scalar()

            wallet_ids = [r.wallet_id for r in c.execute(
                text("SELECT wallet_id FROM offline_wallets ORDER BY wallet_id LIMIT :n"), {"n": LIST_LIMIT})]
            return {
                "policies": docs("SELECT doc FROM policies ORDER BY policy_id LIMIT :n"),
                "merchants": [_merchant_from(r).to_dict() for r in c.execute(
                    text("SELECT * FROM merchants ORDER BY merchant_id LIMIT :n"), {"n": LIST_LIMIT})],
                "utxos": [_utxo_from(r).to_dict() for r in c.execute(
                    text("SELECT * FROM utxos ORDER BY created_at DESC, utxo_id LIMIT :n"), {"n": LIST_LIMIT})],
                "transfer_history": docs("SELECT doc FROM transfers ORDER BY seq DESC LIMIT 25")[::-1],
                "treasury_sweeps": docs("SELECT doc FROM sweeps ORDER BY swept_at, utxo_id LIMIT :n"),
                "offline_wallets": [self._wallet(c, w, with_coins=True, unseal=False).to_public_dict() for w in wallet_ids],
                "pending_offline_packets": docs("SELECT doc FROM offline_packets WHERE status = 'PENDING' ORDER BY seq LIMIT :n"),
                "double_spend_alerts": docs("SELECT doc FROM double_spend_alerts ORDER BY seq LIMIT :n"),
                "metrics": {
                    "total_utxos": count("SELECT COUNT(*) FROM utxos"),
                    "unspent_utxos": count("SELECT COUNT(*) FROM utxos WHERE status = 'UNSPENT'"),
                    "total_transfers": count("SELECT COUNT(*) FROM transfers"),
                    "approved_transfers": count("SELECT COUNT(*) FROM transfers WHERE approved = 1"),
                    "blocked_transfers": count("SELECT COUNT(*) FROM transfers WHERE approved = 0"),
                    "swept_utxos": count("SELECT COUNT(*) FROM sweeps"),
                    "pending_offline_count": count("SELECT COUNT(*) FROM offline_packets WHERE status = 'PENDING'"),
                    "double_spend_alerts_count": count("SELECT COUNT(*) FROM double_spend_alerts"),
                },
            }

        return self._read(run)


def seed_demo(ledger: CBDCLedger) -> CBDCLedger:
    """Demo merchants, purpose-bound UTXOs and offline wallets (all invented)."""
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
    ledger.mint_utxo(owner_id="FARMER-RAMESH-MH", amount_paise=1_200_000, policy_id="PBM-AGRI-01", utxo_id="UTXO-AGRI-101")
    ledger.mint_utxo(owner_id="BENEFICIARY-PRIYA-MH", amount_paise=350_000, policy_id="PBM-FOOD-02", utxo_id="UTXO-FOOD-102")
    ledger.mint_utxo(owner_id="PATIENT-ANIL-DL", amount_paise=4_500_000, policy_id="PBM-HEALTH-03", utxo_id="UTXO-HEALTH-103")
    # Seed an expiring subsidy UTXO for testing expiry clawback
    expired_policy = PBMPolicy(
        policy_id="PBM-DROUGHT-EXP",
        name="Kharif 2025 Drought Relief Voucher (Expired)",
        description="Time-bound relief voucher with expiry timestamp 1700000000; auto-sweeps back to Ministry of Agriculture upon expiry.",
        sponsor_id="MINISTRY-AGRI-TREASURY",
        allowed_mccs={5191, 5261},
        blocked_mccs={7995, 6011},
        allowed_regions={"IN-MH", "IN-KA"},
        max_tx_paise=1_500_000,
        expires_at=1_700_000_000,
        unwrap_on_settlement=True,
        require_verified_merchant=True,
    )
    ledger.mint_utxo(
        owner_id="FARMER-SURESH-KA",
        amount_paise=800_000,
        custom_policy=expired_policy,
        utxo_id="UTXO-EXP-104",
        created_at=1_690_000_000,
    )

    # Seed offline NFC wallets & coins
    w1 = ledger.register_offline_wallet(
        wallet_id="WALLET-NFC-01",
        owner_name="Kavita Deshmukh (Honest Rural NFC User)",
        collateral_paise=1_500_000,
    )
    ledger.mint_offline_coin(wallet_id=w1.wallet_id, amount_paise=50_000, coin_id="OFFCOIN-NFC01-001")
    ledger.mint_offline_coin(wallet_id=w1.wallet_id, amount_paise=100_000, coin_id="OFFCOIN-NFC01-002")

    w2 = ledger.register_offline_wallet(
        wallet_id="WALLET-NFC-02",
        owner_name="Vikram Rogue (Cloned Secure Element Attacker)",
        collateral_paise=2_000_000,
    )
    ledger.mint_offline_coin(wallet_id=w2.wallet_id, amount_paise=200_000, coin_id="OFFCOIN-NFC02-001")

    return ledger


def build_demo_ledger(**kwargs: Any) -> CBDCLedger:
    """A new ledger (in memory unless an engine is given) with the demo data."""
    return seed_demo(CBDCLedger(**kwargs))
