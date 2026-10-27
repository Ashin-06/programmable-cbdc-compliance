"""Money is integer paise inside the ledger; rupees appear only at the edges, as decimal strings."""
from __future__ import annotations

from decimal import Decimal, InvalidOperation


def rupees(paise: int) -> str:
    """600050 -> '6000.50'."""
    return f"{Decimal(paise).scaleb(-2):.2f}"


def to_paise(amount: object) -> int:
    """Rupees as int, Decimal or decimal string (at most two decimals) -> paise. Floats are
    refused: 0.1 + 0.2 is not 0.3, and a ledger should not guess."""
    if isinstance(amount, (float, bool)):
        raise ValueError("amounts must be integers, Decimals or decimal strings, not floats")
    try:
        d = Decimal(str(amount))
    except InvalidOperation as e:
        raise ValueError("amount is not a number") from e
    if not d.is_finite() or d != d.quantize(Decimal("0.01")):
        raise ValueError("amount must be finite with at most two decimals")
    return int(d * 100)


if __name__ == "__main__":
    assert rupees(600050) == "6000.50" and rupees(5) == "0.05" and rupees(-150) == "-1.50"
    assert to_paise("6000.5") == 600050 and to_paise(Decimal("0.10")) == 10 and to_paise(7) == 700
    for bad in (0.1, "1.234", "nan", "inf", "x"):
        try:
            to_paise(bad)
        except ValueError:
            continue
        raise AssertionError(bad)
    print("ok")
