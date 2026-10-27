"""Purpose-Bound Money (PBM) Policy DSL & Deterministic Stack VM for Programmable CBDC (e-Rupee)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cbdcguard.money import rupees


class OpCode(str, Enum):
    """Deterministic Stack VM opcodes for Purpose-Bound Money (PBM) spend verification."""

    LOAD_CTX = "LOAD_CTX"
    PUSH_CONST = "PUSH_CONST"
    OP_IN_SET = "OP_IN_SET"
    OP_NOT_IN_SET = "OP_NOT_IN_SET"
    OP_LTE = "OP_LTE"
    OP_GTE = "OP_GTE"
    OP_EQ = "OP_EQ"
    OP_ASSERT = "OP_ASSERT"
    OP_CHECK_EXPIRY = "OP_CHECK_EXPIRY"
    OP_CHECK_UNWRAP = "OP_CHECK_UNWRAP"
    OP_HALT = "OP_HALT"


@dataclass(frozen=True)
class Instruction:
    """Single bytecode instruction in the PBM Policy Stack VM."""

    opcode: OpCode
    operand: Any = None
    reason_code: str = ""
    comment: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "opcode": self.opcode.value,
            "operand": list(self.operand) if isinstance(self.operand, (set, frozenset)) else self.operand,
            "reason_code": self.reason_code,
            "comment": self.comment,
        }


@dataclass
class PBMPolicy:
    """Declarative Purpose-Bound Money (PBM) Policy attached to a CBDC UTXO."""

    policy_id: str
    name: str
    description: str = ""
    sponsor_id: str = "RBI-TREASURY"
    allowed_mccs: set[int] = field(default_factory=set)
    blocked_mccs: set[int] = field(default_factory=lambda: {7995, 6011})
    allowed_regions: set[str] = field(default_factory=set)
    max_tx_paise: int | None = None
    expires_at: int | None = None
    unwrap_on_settlement: bool = True
    require_verified_merchant: bool = True
    min_kyc_tier: int = 1
    is_general_purpose: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "sponsor_id": self.sponsor_id,
            "allowed_mccs": sorted(self.allowed_mccs),
            "blocked_mccs": sorted(self.blocked_mccs),
            "allowed_regions": sorted(self.allowed_regions),
            "max_tx_amount": rupees(self.max_tx_paise) if self.max_tx_paise is not None else None,
            "max_tx_paise": self.max_tx_paise,
            "expires_at": self.expires_at,
            "unwrap_on_settlement": self.unwrap_on_settlement,
            "require_verified_merchant": self.require_verified_merchant,
            "min_kyc_tier": self.min_kyc_tier,
            "is_general_purpose": self.is_general_purpose,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PBMPolicy:
        return cls(
            policy_id=d["policy_id"], name=d["name"], description=d["description"], sponsor_id=d["sponsor_id"],
            allowed_mccs=set(d["allowed_mccs"]), blocked_mccs=set(d["blocked_mccs"]),
            allowed_regions=set(d["allowed_regions"]), max_tx_paise=d["max_tx_paise"], expires_at=d["expires_at"],
            unwrap_on_settlement=d["unwrap_on_settlement"], require_verified_merchant=d["require_verified_merchant"],
            min_kyc_tier=d["min_kyc_tier"], is_general_purpose=d["is_general_purpose"],
        )


@dataclass(frozen=True)
class SpendContext:
    """Transaction execution context supplied to the PBM Policy Stack VM."""

    merchant_id: str
    merchant_mcc: int
    merchant_region: str
    merchant_verified: bool
    amount_paise: int
    timestamp: int
    sender_kyc_tier: int = 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "merchant_id": self.merchant_id,
            "merchant_mcc": self.merchant_mcc,
            "merchant_region": self.merchant_region,
            "merchant_verified": self.merchant_verified,
            "amount_paise": self.amount_paise,
            "timestamp": self.timestamp,
            "sender_kyc_tier": self.sender_kyc_tier,
        }


@dataclass
class PolicyEvalResult:
    """Result of executing a compiled PBM Policy program on the Deterministic Stack VM."""

    allowed: bool
    policy_id: str
    violation_code: str | None = None
    violation_detail: str | None = None
    is_expired: bool = False
    should_sweep_to_sponsor: bool = False
    should_unwrap: bool = False
    gas_used: int = 0
    trace: list[str] = field(default_factory=list)
    bytecode: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "policy_id": self.policy_id,
            "violation_code": self.violation_code,
            "violation_detail": self.violation_detail,
            "is_expired": self.is_expired,
            "should_sweep_to_sponsor": self.should_sweep_to_sponsor,
            "should_unwrap": self.should_unwrap,
            "gas_used": self.gas_used,
            "trace": self.trace,
            "bytecode": self.bytecode,
        }


class PolicyCompiler:
    """Compiles a declarative PBMPolicy into deterministic Stack VM bytecode instructions."""

    @staticmethod
    def compile(policy: PBMPolicy) -> list[Instruction]:
        program: list[Instruction] = []

        # 1. Expiry guard (checked first so expired vouchers trigger clawback/sweep)
        if policy.expires_at is not None:
            program.append(
                Instruction(
                    opcode=OpCode.LOAD_CTX,
                    operand="timestamp",
                    comment="Load current transaction timestamp",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.PUSH_CONST,
                    operand=policy.expires_at,
                    comment=f"Push policy expiry timestamp ({policy.expires_at})",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_CHECK_EXPIRY,
                    operand=policy.sponsor_id,
                    reason_code="ERR_UTXO_EXPIRED_CLAWBACK",
                    comment=f"Verify timestamp <= {policy.expires_at} or sweep to {policy.sponsor_id}",
                )
            )

        # 2. Sender KYC tier check
        if policy.min_kyc_tier > 0:
            program.append(
                Instruction(
                    opcode=OpCode.LOAD_CTX,
                    operand="sender_kyc_tier",
                    comment="Load sender KYC tier",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.PUSH_CONST,
                    operand=policy.min_kyc_tier,
                    comment=f"Push minimum required KYC tier ({policy.min_kyc_tier})",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_GTE,
                    comment="Check sender_kyc_tier >= min_kyc_tier",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_ASSERT,
                    reason_code="ERR_KYC_TIER_INSUFFICIENT",
                    comment=f"Assert sender KYC tier >= {policy.min_kyc_tier}",
                )
            )

        # 3. Blocked MCC check (e.g. 7995 gambling, 6011 ATM cash-out)
        if policy.blocked_mccs:
            program.append(
                Instruction(
                    opcode=OpCode.LOAD_CTX,
                    operand="merchant_mcc",
                    comment="Load merchant MCC code",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.PUSH_CONST,
                    operand=frozenset(policy.blocked_mccs),
                    comment=f"Push blocked MCC set {sorted(policy.blocked_mccs)}",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_NOT_IN_SET,
                    comment="Check merchant_mcc NOT IN blocked_mccs",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_ASSERT,
                    reason_code="ERR_MCC_BLOCKED",
                    comment="Reject prohibited MCCs (gambling/cash-out)",
                )
            )

        # 4. Allowed MCC whitelist check (for purpose-bound tokens)
        if policy.allowed_mccs and not policy.is_general_purpose:
            program.append(
                Instruction(
                    opcode=OpCode.LOAD_CTX,
                    operand="merchant_mcc",
                    comment="Load merchant MCC code",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.PUSH_CONST,
                    operand=frozenset(policy.allowed_mccs),
                    comment=f"Push allowed MCC whitelist {sorted(policy.allowed_mccs)}",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_IN_SET,
                    comment="Check merchant_mcc IN allowed_mccs",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_ASSERT,
                    reason_code="ERR_MCC_NOT_ALLOWED",
                    comment="Enforce Purpose-Bound MCC restriction",
                )
            )

        # 5. Geographic region fence check (e.g. {"IN-MH", "IN-KA"})
        if policy.allowed_regions and not policy.is_general_purpose:
            program.append(
                Instruction(
                    opcode=OpCode.LOAD_CTX,
                    operand="merchant_region",
                    comment="Load merchant ISO region code",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.PUSH_CONST,
                    operand=frozenset(policy.allowed_regions),
                    comment=f"Push allowed regions {sorted(policy.allowed_regions)}",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_IN_SET,
                    comment="Check merchant_region IN allowed_regions",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_ASSERT,
                    reason_code="ERR_REGION_OUT_OF_BOUNDS",
                    comment="Enforce regional geofence",
                )
            )

        # 6. Per-transaction ceiling check
        if policy.max_tx_paise is not None:
            program.append(
                Instruction(
                    opcode=OpCode.LOAD_CTX,
                    operand="amount_paise",
                    comment="Load spend amount (paise)",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.PUSH_CONST,
                    operand=int(policy.max_tx_paise),
                    comment=f"Push max_tx_paise ceiling ({policy.max_tx_paise})",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_LTE,
                    comment="Check amount_paise <= max_tx_paise",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_ASSERT,
                    reason_code="ERR_MAX_TX_AMOUNT_EXCEEDED",
                    comment="Enforce per-transaction spend ceiling",
                )
            )

        # 7. Verified merchant check (for purpose-bound tokens)
        if policy.require_verified_merchant and not policy.is_general_purpose:
            program.append(
                Instruction(
                    opcode=OpCode.LOAD_CTX,
                    operand="merchant_verified",
                    comment="Load merchant CBDC KYC verification flag",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.PUSH_CONST,
                    operand=True,
                    comment="Push True",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_EQ,
                    comment="Check merchant_verified == True",
                )
            )
            program.append(
                Instruction(
                    opcode=OpCode.OP_ASSERT,
                    reason_code="ERR_MERCHANT_UNVERIFIED",
                    comment="Require verified merchant for PBM settlement",
                )
            )

        # 8. Unwrap-on-settlement trigger
        program.append(
            Instruction(
                opcode=OpCode.OP_CHECK_UNWRAP,
                operand=bool(policy.unwrap_on_settlement and not policy.is_general_purpose),
                comment="Evaluate whether PBM token unwraps into general-purpose e-Rupee upon settlement",
            )
        )

        program.append(Instruction(opcode=OpCode.OP_HALT, comment="Halt VM execution"))
        return program


class PolicyStackVM:
    """Deterministic Stack Virtual Machine for executing compiled PBM bytecode."""

    GAS_PER_OP = 5

    @classmethod
    def evaluate(cls, policy: PBMPolicy, ctx: SpendContext) -> PolicyEvalResult:
        program = PolicyCompiler.compile(policy)
        bytecode_dicts = [instr.to_dict() for instr in program]
        stack: list[Any] = []
        trace: list[str] = []
        gas_used = 0
        should_unwrap = False

        ctx_map = ctx.to_dict()

        for pc, instr in enumerate(program):
            gas_used += cls.GAS_PER_OP
            op = instr.opcode

            if op == OpCode.LOAD_CTX:
                val = ctx_map[instr.operand]
                stack.append(val)
                trace.append(f"[{pc:02d}] LOAD_CTX({instr.operand}) -> {val!r}")

            elif op == OpCode.PUSH_CONST:
                stack.append(instr.operand)
                disp = sorted(instr.operand) if isinstance(instr.operand, (set, frozenset)) else instr.operand
                trace.append(f"[{pc:02d}] PUSH_CONST({disp!r})")

            elif op == OpCode.OP_IN_SET:
                allowed_set = stack.pop()
                item = stack.pop()
                res = item in allowed_set
                stack.append(res)
                trace.append(f"[{pc:02d}] OP_IN_SET({item!r} in {sorted(allowed_set)}) -> {res}")

            elif op == OpCode.OP_NOT_IN_SET:
                blocked_set = stack.pop()
                item = stack.pop()
                res = item not in blocked_set
                stack.append(res)
                trace.append(f"[{pc:02d}] OP_NOT_IN_SET({item!r} not in {sorted(blocked_set)}) -> {res}")

            elif op == OpCode.OP_LTE:
                rhs = stack.pop()
                lhs = stack.pop()
                res = lhs <= rhs
                stack.append(res)
                trace.append(f"[{pc:02d}] OP_LTE({lhs} <= {rhs}) -> {res}")

            elif op == OpCode.OP_GTE:
                rhs = stack.pop()
                lhs = stack.pop()
                res = lhs >= rhs
                stack.append(res)
                trace.append(f"[{pc:02d}] OP_GTE({lhs} >= {rhs}) -> {res}")

            elif op == OpCode.OP_EQ:
                rhs = stack.pop()
                lhs = stack.pop()
                res = lhs == rhs
                stack.append(res)
                trace.append(f"[{pc:02d}] OP_EQ({lhs!r} == {rhs!r}) -> {res}")

            elif op == OpCode.OP_CHECK_EXPIRY:
                expiry_ts = stack.pop()
                current_ts = stack.pop()
                not_expired = current_ts <= expiry_ts
                trace.append(
                    f"[{pc:02d}] OP_CHECK_EXPIRY(ts={current_ts} <= expires_at={expiry_ts}) -> {not_expired}"
                )
                if not not_expired:
                    return PolicyEvalResult(
                        allowed=False,
                        policy_id=policy.policy_id,
                        violation_code=instr.reason_code or "ERR_UTXO_EXPIRED_CLAWBACK",
                        violation_detail=(
                            f"Token expired at {expiry_ts} (tx timestamp {current_ts}); "
                            f"flagged for auto-sweep clawback to sponsor '{instr.operand}'."
                        ),
                        is_expired=True,
                        should_sweep_to_sponsor=True,
                        should_unwrap=False,
                        gas_used=gas_used,
                        trace=trace,
                        bytecode=bytecode_dicts,
                    )

            elif op == OpCode.OP_ASSERT:
                cond = bool(stack.pop())
                trace.append(f"[{pc:02d}] OP_ASSERT({instr.reason_code}) -> {'PASS' if cond else 'FAIL'}")
                if not cond:
                    return PolicyEvalResult(
                        allowed=False,
                        policy_id=policy.policy_id,
                        violation_code=instr.reason_code,
                        violation_detail=cls._format_violation_detail(instr.reason_code, policy, ctx),
                        is_expired=False,
                        should_sweep_to_sponsor=False,
                        should_unwrap=False,
                        gas_used=gas_used,
                        trace=trace,
                        bytecode=bytecode_dicts,
                    )

            elif op == OpCode.OP_CHECK_UNWRAP:
                should_unwrap = bool(instr.operand and ctx.merchant_verified)
                trace.append(f"[{pc:02d}] OP_CHECK_UNWRAP -> should_unwrap={should_unwrap}")

            elif op == OpCode.OP_HALT:
                trace.append(f"[{pc:02d}] OP_HALT -> ALLOW (gas={gas_used})")
                break

        return PolicyEvalResult(
            allowed=True,
            policy_id=policy.policy_id,
            violation_code=None,
            violation_detail=None,
            is_expired=False,
            should_sweep_to_sponsor=False,
            should_unwrap=should_unwrap,
            gas_used=gas_used,
            trace=trace,
            bytecode=bytecode_dicts,
        )

    @staticmethod
    def _format_violation_detail(reason_code: str, policy: PBMPolicy, ctx: SpendContext) -> str:
        if reason_code == "ERR_MCC_BLOCKED":
            return (
                f"Merchant MCC {ctx.merchant_mcc} is in blocked MCC set {sorted(policy.blocked_mccs)} "
                f"(e.g., gambling 7995 / ATM cash-out 6011)."
            )
        if reason_code == "ERR_MCC_NOT_ALLOWED":
            return (
                f"Merchant MCC {ctx.merchant_mcc} is not permitted by policy '{policy.name}'; "
                f"allowed MCCs: {sorted(policy.allowed_mccs)}."
            )
        if reason_code == "ERR_REGION_OUT_OF_BOUNDS":
            return (
                f"Merchant region '{ctx.merchant_region}' is outside policy geofence "
                f"{sorted(policy.allowed_regions)}."
            )
        if reason_code == "ERR_MAX_TX_AMOUNT_EXCEEDED":
            return (
                f"Transaction amount ₹{rupees(ctx.amount_paise)} exceeds per-transaction ceiling "
                f"₹{rupees(policy.max_tx_paise or 0)}."
            )
        if reason_code == "ERR_MERCHANT_UNVERIFIED":
            return f"Merchant '{ctx.merchant_id}' is not a verified CBDC merchant."
        if reason_code == "ERR_KYC_TIER_INSUFFICIENT":
            return (
                f"Sender KYC tier {ctx.sender_kyc_tier} is below minimum required tier {policy.min_kyc_tier}."
            )
        return f"Policy check failed with code {reason_code}."


def build_preset_policies() -> dict[str, PBMPolicy]:
    """
    Illustrative purpose-bound money policies. They are invented examples, not RBI rules or the
    terms of any real government scheme.
    """

    return {
        "PBM-AGRI-01": PBMPolicy(
            policy_id="PBM-AGRI-01",
            name="Agricultural Input Subsidy (Seeds & Fertiliser)",
            description="Purpose-bound agricultural input voucher restricted to seed & fertilizer merchants (MCC 5191, 5261) in Maharashtra & Karnataka.",
            sponsor_id="MINISTRY-AGRI-TREASURY",
            allowed_mccs={5191, 5261},
            blocked_mccs={7995, 6011},
            allowed_regions={"IN-MH", "IN-KA", "IN-PB", "IN-UP"},
            max_tx_paise=2_500_000,
            expires_at=1_900_000_000,
            unwrap_on_settlement=True,
            require_verified_merchant=True,
            min_kyc_tier=1,
            is_general_purpose=False,
        ),
        "PBM-FOOD-02": PBMPolicy(
            policy_id="PBM-FOOD-02",
            name="Food & Grocery Voucher",
            description="Food security CBDC token redeemable only at verified grocery & food outlets (MCC 5411, 5812).",
            sponsor_id="FOOD-VOUCHER-SPONSOR",
            allowed_mccs={5411, 5812},
            blocked_mccs={7995, 6011},
            allowed_regions={"IN-MH", "IN-KA", "IN-DL", "IN-TN", "IN-UP", "IN-WB"},
            max_tx_paise=500_000,
            expires_at=1_900_000_000,
            unwrap_on_settlement=True,
            require_verified_merchant=True,
            min_kyc_tier=1,
            is_general_purpose=False,
        ),
        "PBM-HEALTH-03": PBMPolicy(
            policy_id="PBM-HEALTH-03",
            name="Healthcare & Hospital Voucher",
            description="Healthcare e-Rupee token restricted to accredited clinics, doctors & hospitals (MCC 8011, 8062, 5912).",
            sponsor_id="HEALTH-VOUCHER-SPONSOR",
            allowed_mccs={8011, 8062, 5912},
            blocked_mccs={7995, 6011},
            allowed_regions={"IN-MH", "IN-KA", "IN-DL", "IN-TN", "IN-GJ", "IN-UP"},
            max_tx_paise=10_000_000,
            expires_at=1_900_000_000,
            unwrap_on_settlement=True,
            require_verified_merchant=True,
            min_kyc_tier=1,
            is_general_purpose=False,
        ),
        "PBM-GENERAL": PBMPolicy(
            policy_id="PBM-GENERAL",
            name="General-Purpose Commercial e-Rupee (e₹-R)",
            description="Unwrapped general-purpose digital rupee after valid PBM merchant settlement; usable across all legal MCCs and regions.",
            sponsor_id="RBI-ISSUE-DEPT",
            allowed_mccs=set(),
            blocked_mccs={7995},  # Illegal offshore gambling still blocked by baseline compliance
            allowed_regions=set(),
            max_tx_paise=50_000_000,
            expires_at=None,
            unwrap_on_settlement=False,
            require_verified_merchant=False,
            min_kyc_tier=1,
            is_general_purpose=True,
        ),
    }
