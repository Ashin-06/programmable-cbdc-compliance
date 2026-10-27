"""
Single-Show Offline CBDC Spends with Double-Spend Identity Recovery.

A wallet holds a secret scalar s with public key S = s*G. Each offline coin carries a fresh
random scalar r with R = r*G, and the issuer (central bank) signs (coin_id, wallet, counter,
amount, S, R) with Ed25519 when the coin is withdrawn. To spend, the merchant terminal derives a
challenge x from its own ID, time, nonce and the coin, and the wallet answers y = s*x + r mod L.
The terminal checks the issuer signature and y*G == x*S + R without going online.

- One answer reveals nothing about s, because r is uniform and used once.
- Two answers to different challenges on the same coin give s = (y1 - y2) / (x1 - x2) mod L,
  which proves the double spend and identifies the wallet.

Group arithmetic is libsodium's Ed25519 prime-order subgroup (through PyNaCl); signatures use
`cryptography`. This is a reference implementation for study, not reviewed cryptography, and it
does not make payments unlinkable: every coin carries the wallet's public key S.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import secrets
from typing import Any

import nacl.bindings as sodium
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from cbdcguard.money import rupees

# Order of the Ed25519 prime-order subgroup
ED25519_L: int = 2**252 + 27742317777372353535851937790883648493
_IDENTITY = bytes([1]) + bytes(31)


def _scalar(k: int) -> bytes:
    return (k % ED25519_L).to_bytes(32, "little")


def _base_mul(k: int) -> bytes:
    k %= ED25519_L
    return _IDENTITY if k == 0 else sodium.crypto_scalarmult_ed25519_base_noclamp(_scalar(k))


def _mul(point: bytes, k: int) -> bytes:
    k %= ED25519_L
    return _IDENTITY if k == 0 else sodium.crypto_scalarmult_ed25519_noclamp(_scalar(k), point)


def random_scalar() -> int:
    return 1 + secrets.randbelow(ED25519_L - 1)


def public_point(secret: int) -> bytes:
    return _base_mul(secret)


def is_prime_order_point(p: Any) -> bool:
    """Canonical, non-identity point of the prime-order subgroup (L*P == identity)."""
    if not (isinstance(p, bytes) and len(p) == 32 and sodium.crypto_core_ed25519_is_valid_point(p)):
        return False
    return sodium.crypto_core_ed25519_add(_mul(p, ED25519_L - 1), p) == _IDENTITY


def derive_challenge_x(merchant_id: str, timestamp: int, nonce: str, coin_id: str) -> int:
    """Terminal challenge x = H(merchant_id || timestamp || nonce || coin_id) in [1, L-1]."""
    payload = "\x1f".join([merchant_id, str(timestamp), nonce, coin_id]).encode("utf-8")
    digest = int.from_bytes(hashlib.sha512(b"cbdcguard.challenge.v2|" + payload).digest(), "big")
    return (digest % (ED25519_L - 1)) + 1


def coin_message(coin_id: str, wallet_id: str, counter: int, amount_paise: int, commitment_s: bytes, commitment_r: bytes) -> bytes:
    """Bytes the issuer signs for an offline coin."""
    return b"|".join([
        b"cbdcguard.offline_coin.v2",
        coin_id.encode("utf-8"),
        wallet_id.encode("utf-8"),
        str(counter).encode(),
        str(amount_paise).encode(),
        commitment_s,
        commitment_r,
    ])


def verify_offline_proof(challenge_x: int, response_y: int, commitment_s: bytes, commitment_r: bytes) -> bool:
    """Check y*G == x*S + R, with S and R in the prime-order subgroup."""
    if not (1 <= challenge_x < ED25519_L and 0 <= response_y < ED25519_L):
        return False
    if not (is_prime_order_point(commitment_s) and is_prime_order_point(commitment_r)):
        return False
    rhs = sodium.crypto_core_ed25519_add(_mul(commitment_s, challenge_x), commitment_r)
    return _base_mul(response_y) == rhs


def recover_double_spend_secret(x1: int, y1: int, x2: int, y2: int) -> tuple[int, int]:
    """
    Recover s and r from two answers on the same coin:
        s = (y1 - y2) * (x1 - x2)^(-1) mod L,  r = (y1 - s * x1) mod L
    """
    dx = (x1 - x2) % ED25519_L
    if dx == 0:
        raise ValueError("Challenges x1 and x2 must be distinct to interpolate L(x) = s*x + r")
    s_recovered = ((y1 - y2) * pow(dx, -1, ED25519_L)) % ED25519_L
    r_recovered = (y1 - s_recovered * x1) % ED25519_L
    return s_recovered, r_recovered


@dataclass
class OfflineCoin:
    """An offline e-Rupee coin minted into a hardware Secure Element with monotonic counter c."""

    coin_id: str
    wallet_id: str
    counter: int
    amount_paise: int
    blinding_r: int | None  # None when loaded for display only
    commitment_s: bytes
    commitment_r: bytes
    issuer_signature: bytes = b""
    spent_count: int = 0  # the wallet's secure-element counter for this coin

    def message(self) -> bytes:
        return coin_message(self.coin_id, self.wallet_id, self.counter, self.amount_paise, self.commitment_s, self.commitment_r)

    def to_public_dict(self) -> dict[str, Any]:
        """Public view of the coin (never exposes blinding_r)."""
        return {
            "coin_id": self.coin_id,
            "wallet_id": self.wallet_id,
            "counter": self.counter,
            "amount": rupees(self.amount_paise),
            "amount_paise": self.amount_paise,
            "commitment_s_hex": self.commitment_s.hex(),
            "commitment_r_hex": self.commitment_r.hex(),
            "issuer_signature_hex": self.issuer_signature.hex(),
            "spent_count": self.spent_count,
        }


@dataclass
class OfflineWallet:
    """Hardware-backed offline CBDC wallet holding secret identity scalar s."""

    wallet_id: str
    owner_name: str
    secret_s: int | None  # None when loaded for display only
    commitment_s: bytes
    collateral_paise: int = 2_500_000
    monotonic_counter: int = 0
    slashed: bool = False
    slashed_paise: int = 0
    recovered_secret_s: int | None = None
    coins: dict[str, OfflineCoin] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        wallet_id: str,
        owner_name: str,
        collateral_paise: int = 2_500_000,
        secret_s: int | None = None,
    ) -> OfflineWallet:
        s = secret_s if secret_s is not None else random_scalar()
        return cls(
            wallet_id=wallet_id,
            owner_name=owner_name,
            secret_s=s,
            commitment_s=public_point(s),
            collateral_paise=collateral_paise,
        )

    def mint_coin(
        self,
        amount_paise: int,
        coin_id: str | None = None,
        blinding_r: int | None = None,
        issuer_key: Ed25519PrivateKey | None = None,
    ) -> OfflineCoin:
        """Create a coin committed to L(x) = s*x + r; the issuer signs it if a key is given."""
        if self.slashed:
            raise ValueError(f"Offline wallet '{self.wallet_id}' is slashed and blacklisted.")
        if not isinstance(amount_paise, int) or amount_paise <= 0:
            raise ValueError("Coin amount must be a positive whole number of paise.")
        cid = coin_id or f"OFFCOIN-{self.wallet_id}-{self.monotonic_counter + 1:03d}"
        if cid in self.coins:
            # Re-minting an existing ID would reset its spend counter and allow a re-spend
            raise ValueError(f"Coin ID '{cid}' already exists in wallet '{self.wallet_id}'.")
        self.monotonic_counter += 1
        r = blinding_r if blinding_r is not None else random_scalar()
        coin = OfflineCoin(
            coin_id=cid,
            wallet_id=self.wallet_id,
            counter=self.monotonic_counter,
            amount_paise=amount_paise,
            blinding_r=r,
            commitment_s=self.commitment_s,
            commitment_r=public_point(r),
        )
        if issuer_key is not None:
            coin.issuer_signature = issuer_key.sign(coin.message())
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
        Evaluate L(x) = s*x + r mod L at the terminal challenge x.
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
        x = derive_challenge_x(merchant_id=merchant_id, timestamp=timestamp, nonce=nonce, coin_id=coin.coin_id)
        y = (self.secret_s * x + coin.blinding_r) % ED25519_L
        coin.spent_count += 1
        return OfflineSpendPacket(
            packet_id=f"PKT-{coin.coin_id}-{coin.spent_count}-{nonce[:6]}",
            coin_id=coin.coin_id,
            wallet_id=self.wallet_id,
            counter=coin.counter,
            amount_paise=coin.amount_paise,
            merchant_id=merchant_id,
            timestamp=timestamp,
            nonce=nonce,
            challenge_x=x,
            response_y=y,
            commitment_s=coin.commitment_s,
            commitment_r=coin.commitment_r,
            issuer_signature=coin.issuer_signature,
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "wallet_id": self.wallet_id,
            "owner_name": self.owner_name,
            "commitment_s_hex": self.commitment_s.hex(),
            "collateral_balance": rupees(self.collateral_paise),
            "collateral_paise": self.collateral_paise,
            "monotonic_counter": self.monotonic_counter,
            "slashed": self.slashed,
            "slashed_amount": rupees(self.slashed_paise),
            "slashed_paise": self.slashed_paise,
            "recovered_secret_s_hex": hex(self.recovered_secret_s) if self.recovered_secret_s is not None else None,
            "coins": [c.to_public_dict() for c in self.coins.values()],
        }


@dataclass(frozen=True)
class OfflineSpendPacket:
    """Single-show proof packet transmitted over NFC to an offline merchant POS terminal."""

    packet_id: str
    coin_id: str
    wallet_id: str
    counter: int
    amount_paise: int
    merchant_id: str
    timestamp: int
    nonce: str
    challenge_x: int
    response_y: int
    commitment_s: bytes
    commitment_r: bytes
    issuer_signature: bytes = b""

    def verify_terminal_proof(self, issuer_public_key: Ed25519PublicKey) -> bool:
        """
        What an offline terminal can check: the issuer signed this coin (so it was really
        withdrawn, for this amount), the challenge is the terminal's own, and y*G == x*S + R.
        """
        try:
            issuer_public_key.verify(
                self.issuer_signature,
                coin_message(self.coin_id, self.wallet_id, self.counter, self.amount_paise,
                             self.commitment_s, self.commitment_r),
            )
        except InvalidSignature:
            return False
        expected_x = derive_challenge_x(self.merchant_id, self.timestamp, self.nonce, self.coin_id)
        if expected_x != self.challenge_x:
            return False
        return verify_offline_proof(self.challenge_x, self.response_y, self.commitment_s, self.commitment_r)

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "coin_id": self.coin_id,
            "wallet_id": self.wallet_id,
            "counter": self.counter,
            "amount": rupees(self.amount_paise),
            "amount_paise": self.amount_paise,
            "merchant_id": self.merchant_id,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "challenge_x_hex": hex(self.challenge_x),
            "response_y_hex": hex(self.response_y),
            "commitment_s_hex": self.commitment_s.hex(),
            "commitment_r_hex": self.commitment_r.hex(),
            "issuer_signature_hex": self.issuer_signature.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> OfflineSpendPacket:
        return cls(
            packet_id=d["packet_id"], coin_id=d["coin_id"], wallet_id=d["wallet_id"], counter=d["counter"],
            amount_paise=d["amount_paise"], merchant_id=d["merchant_id"], timestamp=d["timestamp"], nonce=d["nonce"],
            challenge_x=int(d["challenge_x_hex"], 16), response_y=int(d["response_y_hex"], 16),
            commitment_s=bytes.fromhex(d["commitment_s_hex"]), commitment_r=bytes.fromhex(d["commitment_r_hex"]),
            issuer_signature=bytes.fromhex(d["issuer_signature_hex"]),
        )


@dataclass
class DoubleSpendAlert:
    """Cryptographic forensics report generated when two offline spends share the same coin/counter."""

    coin_id: str
    wallet_id: str
    owner_name: str
    counter: int
    amount_per_spend_paise: int
    merchant_1: str
    merchant_2: str
    x1: int
    y1: int
    x2: int
    y2: int
    recovered_secret_s: int
    recovered_blinding_r: int
    commitment_s: bytes
    verified_against_commitment: bool
    slashed_paise: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "coin_id": self.coin_id,
            "wallet_id": self.wallet_id,
            "owner_name": self.owner_name,
            "counter": self.counter,
            "amount_per_spend": rupees(self.amount_per_spend_paise),
            "amount_per_spend_paise": self.amount_per_spend_paise,
            "merchant_1": self.merchant_1,
            "merchant_2": self.merchant_2,
            "x1_hex": hex(self.x1),
            "y1_hex": hex(self.y1),
            "x2_hex": hex(self.x2),
            "y2_hex": hex(self.y2),
            "recovered_secret_s_hex": hex(self.recovered_secret_s),
            "recovered_blinding_r_hex": hex(self.recovered_blinding_r),
            "commitment_s_hex": self.commitment_s.hex(),
            "verified_against_commitment": self.verified_against_commitment,
            "slashed_collateral": rupees(self.slashed_paise),
            "slashed_paise": self.slashed_paise,
            "formula": "s = (y1 - y2) * (x1 - x2)^(-1) mod L",
        }
