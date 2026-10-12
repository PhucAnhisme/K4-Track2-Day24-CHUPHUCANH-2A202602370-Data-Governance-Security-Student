"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call.

Interface bắt buộc:
    check(context: PolicyContext) -> tuple[bool, str]
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict[str, dict]:
    if not PRINCIPALS_PATH.exists():
        return {}
    return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra quyền truy cập trước khi thực thi tool.

    Mọi quyết định đều trả về (allow, reason) với reason không bao giờ rỗng.
    """
    # 1. Minimum deny rule: dữ liệu restricted không bao giờ được đi kèm egress
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "DENY: restricted data with egress enabled is strictly prohibited"

    # 2. Kiểm tra thời hạn hiệu lực (TTL) nếu có
    if context.expires_at:
        try:
            exp = datetime.fromisoformat(context.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                return False, f"DENY: authorization expired at {context.expires_at}"
        except Exception:
            return False, f"DENY: invalid expires_at timestamp {context.expires_at!r}"

    # 3. Kiểm tra principal nếu được cung cấp
    if context.principal_id:
        principals = _load_principals()
        if context.principal_id not in principals:
            return False, f"DENY: unknown principal {context.principal_id!r}"

        principal_info = principals[context.principal_id]
        allowed_tools = set(principal_info.get("allowed_tools", []))
        allowed_purposes = set(principal_info.get("purposes", []))

        # Kiểm tra mục đích yêu cầu (purpose)
        if context.request_purpose and context.request_purpose not in allowed_purposes:
            return False, (
                f"DENY: purpose {context.request_purpose!r} is not authorized for "
                f"principal {context.principal_id}"
            )

        # Tính toán effective scopes: giao giữa principal.allowed_tools và agent_scopes
        effective_tools = set(allowed_tools)
        if context.agent_scopes:
            effective_tools &= set(context.agent_scopes)

        # Nếu có uỷ quyền (delegation_depth > 0), giao tiếp với parent_scopes
        if context.delegation_depth > 0 and context.parent_scopes:
            effective_tools &= set(context.parent_scopes)

        # Kiểm tra tool sắp gọi có nằm trong effective tools không
        if context.requested_tool and context.requested_tool not in effective_tools:
            return False, (
                f"DENY: tool {context.requested_tool!r} is not in effective permissions for "
                f"principal {context.principal_id}"
            )

    return True, f"ALLOW: policy check passed for {context.requested_tool or context.agent_owner}"
