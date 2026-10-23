"""Cut-and-Choose / Single-Show Polynomial Offline CBDC Double-Spend Identity Recovery."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import secrets
from typing import Any

# Safe prime p = 2*q + 1 (128-bit Schnorr subgroup G_q of prime order q with generator g = 4)
PRIME_Q: int = 170141183460469231731687303715884111953
PRIME_P: int = 340282366920938463463374607431768223907
GENERATOR_G: int = 4


def derive_challenge_x(merchant_id: str, timestamp: int, nonce: str, q: int = PRIME_Q) -> int:
    """Compute merchant terminal challenge x = H(merchant_id || timestamp || nonce) mod q in [1, q-1]."""
    payload = f"{merchant_id}||{timestamp}||{nonce}".encode("utf-8")
    digest = int.from_bytes(hashlib.sha256(payload).digest(), byteorder="big")
    return (digest % (q - 1)) + 1


def verify_offline_proof(
    challenge_x: int,
    response_y: int,
    commitment_s: int,
    commitment_r: int,
    p: int = PRIME_P,
    q: int = PRIME_Q,
    g: int = GENERATOR_G,
) -> bool:
    """
    Verify offline spend proof without central bank connectivity:
        g^y == (g^s)^x * g^r (mod p)
    Since g has prime order q modulo p, exponent arithmetic mod q maps homomorphically to mod p.
    """
    if not (1 <= challenge_x < q and 0 <= response_y < q):
        return False
    lhs = pow(g, response_y, p)
    rhs = (pow(commitment_s, challenge_x, p) * (commitment_r % p)) % p
    return lhs == rhs


def recover_double_spend_secret(
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    q: int = PRIME_Q,
) -> tuple[int, int]:
    """
    Recover the spender's secret identity scalar s and per-coin blinding scalar r
    from two distinct challenge-response transcripts (x1, y1) and (x2, y2) on the same coin:
        s = (y1 - y2) * (x1 - x2)^(-1) mod q
        r = (y1 - s * x1) mod q
    """
    dx = (x1 - x2) % q
    if dx == 0:
        raise ValueError("Challenges x1 and x2 must be distinct to interpolate line L(x) = s*x + r mod q")
    inv_dx = pow(dx, -1, q)
    s_recovered = ((y1 - y2) * inv_dx) % q
    r_recovered = (y1 - s_recovered * x1) % q
    return s_recovered, r_recovered


@dataclass
class OfflineCoin:
    """An offline e-Rupee coin minted into a hardware Secure Element with monotonic counter c."""

    coin_id: str
    wallet_id: str
    counter: int
    amount: float
    blinding_r: int
    commitment_s: int
    commitment_r: int
    spent_count: int = 0

    def to_public_dict(self) -> dict[str, Any]:
        """Public view of the coin (never exposes blinding_r)."""
        return {
            "coin_id": self.coin_id,
            "wallet_id": self.wallet_id,
            "counter": self.counter,
            "amount": self.amount,
            "commitment_s_hex": hex(self.commitment_s),
            "commitment_r_hex": hex(self.commitment_r),
            "spent_count": self.spent_count,
        }


@dataclass
class OfflineWallet:
    """Hardware-backed offline CBDC wallet holding secret identity scalar s in F_q."""

    wallet_id: str
    owner_name: str
    secret_s: int
    commitment_s: int
    collateral_balance: float = 25000.0
    monotonic_counter: int = 0
    slashed: bool = False
    slashed_amount: float = 0.0
    recovered_secret_s: int | None = None
    coins: dict[str, OfflineCoin] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        wallet_id: str,
        owner_name: str,
        collateral_balance: float = 25000.0,
        secret_s: int | None = None,
    ) -> OfflineWallet:
        s = secret_s if secret_s is not None else (secrets.randbelow(PRIME_Q - 2) + 2)
        comm_s = pow(GENERATOR_G, s, PRIME_P)
        return cls(
            wallet_id=wallet_id,
            owner_name=owner_name,
            secret_s=s,
            commitment_s=comm_s,
            collateral_balance=collateral_balance,
        )

    def mint_coin(
        self,
        amount: float,
        coin_id: str | None = None,
        blinding_r: int | None = None,
    ) -> OfflineCoin:
        """Mint an offline coin committed to L(x) = (s*x + r) mod q with incremented monotonic counter."""
        if self.slashed:
            raise ValueError(f"Offline wallet '{self.wallet_id}' is slashed and blacklisted.")
        self.monotonic_counter += 1
        r = blinding_r if blinding_r is not None else (secrets.randbelow(PRIME_Q - 2) + 2)
        comm_r = pow(GENERATOR_G, r, PRIME_P)
        cid = coin_id or f"OFFCOIN-{self.wallet_id}-{self.monotonic_counter:03d}"
        coin = OfflineCoin(
            coin_id=cid,
            wallet_id=self.wallet_id,
            counter=self.monotonic_counter,
            amount=float(amount),
            blinding_r=r,
            commitment_s=self.commitment_s,
            commitment_r=comm_r,
        )
        self.coins[cid] = coin
        return coin

    def sign_offline_spend(
        self,
        coin_id: str,
        merchant_id: str,
        timestamp: int,
        nonce: str,
        allow_counter_rollback: bool = False,
    ) -> OfflineSpendPacket:
        """
        Evaluate polynomial L(x) = (s * x + r) mod q at terminal challenge x.
        If coin was already spent and allow_counter_rollback=False, Secure Element blocks re-spend.
        If allow_counter_rollback=True (simulating physical fault injection / cloned SE), produces a 2nd transcript.
        """
        if coin_id not in self.coins:
            raise KeyError(f"Unknown offline coin '{coin_id}' in wallet '{self.wallet_id}'.")
        coin = self.coins[coin_id]
        if coin.spent_count >= 1 and not allow_counter_rollback:
            raise ValueError(
                f"Hardware monotonic counter guard blocked re-spend of coin '{coin_id}' "
                f"(counter={coin.counter}). Set allow_counter_rollback=True to simulate clone attack."
            )
        x = derive_challenge_x(merchant_id=merchant_id, timestamp=timestamp, nonce=nonce)
        y = (self.secret_s * x + coin.blinding_r) % PRIME_Q
        coin.spent_count += 1
        return OfflineSpendPacket(
            packet_id=f"PKT-{coin.coin_id}-{coin.spent_count}-{nonce[:6]}",
            coin_id=coin.coin_id,
            wallet_id=self.wallet_id,
            counter=coin.counter,
            amount=coin.amount,
            merchant_id=merchant_id,
            timestamp=timestamp,
            nonce=nonce,
            challenge_x=x,
            response_y=y,
            commitment_s=coin.commitment_s,
            commitment_r=coin.commitment_r,
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "wallet_id": self.wallet_id,
            "owner_name": self.owner_name,
            "commitment_s_hex": hex(self.commitment_s),
            "collateral_balance": self.collateral_balance,
            "monotonic_counter": self.monotonic_counter,
            "slashed": self.slashed,
            "slashed_amount": self.slashed_amount,
            "recovered_secret_s_hex": hex(self.recovered_secret_s) if self.recovered_secret_s is not None else None,
            "coins": [c.to_public_dict() for c in self.coins.values()],
        }


@dataclass(frozen=True)
class OfflineSpendPacket:
    """Single-show polynomial proof packet transmitted over NFC to an offline merchant POS terminal."""

    packet_id: str
    coin_id: str
    wallet_id: str
    counter: int
    amount: float
    merchant_id: str
    timestamp: int
    nonce: str
    challenge_x: int
    response_y: int
    commitment_s: int
    commitment_r: int

    def verify_terminal_proof(self) -> bool:
        """Verify g^y == (g^s)^x * g^r (mod p) offline at the merchant terminal."""
        expected_x = derive_challenge_x(self.merchant_id, self.timestamp, self.nonce)
        if expected_x != self.challenge_x:
            return False
        return verify_offline_proof(
            challenge_x=self.challenge_x,
            response_y=self.response_y,
            commitment_s=self.commitment_s,
            commitment_r=self.commitment_r,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "coin_id": self.coin_id,
            "wallet_id": self.wallet_id,
            "counter": self.counter,
            "amount": self.amount,
            "merchant_id": self.merchant_id,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "challenge_x_hex": hex(self.challenge_x),
            "response_y_hex": hex(self.response_y),
            "commitment_s_hex": hex(self.commitment_s),
            "commitment_r_hex": hex(self.commitment_r),
            "proof_valid": self.verify_terminal_proof(),
        }


@dataclass
class DoubleSpendAlert:
    """Cryptographic forensics report generated when two offline spends share the same coin/counter."""

    coin_id: str
    wallet_id: str
    owner_name: str
    counter: int
    amount_per_spend: float
    merchant_1: str
    merchant_2: str
    x1: int
    y1: int
    x2: int
    y2: int
    recovered_secret_s: int
    recovered_blinding_r: int
    commitment_s: int
    verified_against_commitment: bool
    slashed_collateral: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "coin_id": self.coin_id,
            "wallet_id": self.wallet_id,
            "owner_name": self.owner_name,
            "counter": self.counter,
            "amount_per_spend": self.amount_per_spend,
            "merchant_1": self.merchant_1,
            "merchant_2": self.merchant_2,
            "x1_hex": hex(self.x1),
            "y1_hex": hex(self.y1),
            "x2_hex": hex(self.x2),
            "y2_hex": hex(self.y2),
            "recovered_secret_s_hex": hex(self.recovered_secret_s),
            "recovered_blinding_r_hex": hex(self.recovered_blinding_r),
            "commitment_s_hex": hex(self.commitment_s),
            "verified_against_commitment": self.verified_against_commitment,
            "slashed_collateral": self.slashed_collateral,
            "formula": "s = (y1 - y2) * (x1 - x2)^(-1) mod q",
        }
