"""BƯỚC 3c — trifecta split + egress allowlist + OBO delegation.

Interface bắt buộc:
    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_PATH = Path(__file__).resolve().parent.parent / "data" / "customers.json"


def _hash_args(args: dict) -> str:
    serialized = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def _extract_ticket_ids_from_filenames(docs: list[dict]) -> list[int]:
    """Trích xuất ID dạng số CHỈ từ tên file (ví dụ: ticket-007.md -> 7).

    Tuyệt đối không lấy từ nội dung text tự do của document.
    """
    ticket_ids = []
    for doc in docs:
        file_name = doc.get("id", "")
        match = re.search(r"ticket-(\d+)", file_name)
        if match:
            ticket_ids.append(int(match.group(1)))
    return sorted(set(ticket_ids))


def _find_customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Tra cứu khách hàng từ nguồn tin cậy data/customers.json dựa trên related_tickets."""
    if not CUSTOMERS_PATH.exists() or not ticket_ids:
        return []
    customers = json.loads(CUSTOMERS_PATH.read_text(encoding="utf-8"))
    matched_ids = []
    ticket_set = set(ticket_ids)
    for cust in customers:
        related = set(cust.get("related_tickets", []))
        if related & ticket_set:
            matched_ids.append(cust["customer_id"])
    return sorted(set(matched_ids))


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Xử lý yêu cầu người dùng bằng Trifecta Split (Run A và Run B riêng biệt)."""
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    run_base_id = uuid.uuid4().hex[:8]
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()

    # ==========================================
    # RUN A: Đọc untrusted content (search_docs)
    # Không có quyền chạm vào private store / network
    # ==========================================
    run_a_id = f"run-{run_base_id}-a"
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs", "read_customer"),
        parent_scopes=(),
        expires_at=expires_at,
    )
    search_allowed, search_reason = policy.check(ctx_search)

    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "on_behalf_of": principal_id,
            "agent_id": "lab24-agent",
            "run_id": run_a_id,
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": "internal",
            "decision": "allow" if search_allowed else "deny",
            "reason": search_reason,
            "expires_at": expires_at,
        },
        ledger_path,
    )

    if not search_allowed:
        return "Yêu cầu bị từ chối do chính sách bảo mật."

    docs = tools.search_docs(message)

    # Sanitize boundary: chỉ lấy ticket_ids dạng số từ tên file sang Run B
    ticket_ids = _extract_ticket_ids_from_filenames(docs)

    # Nhận diện injection trong Run A (để audit và xử lý ngăn chặn)
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # ==========================================
    # RUN B: Truy cập private data store (read_customer)
    # Khách hàng được suy ra từ NGUỒN TIN CẬY (data/customers.json),
    # không bao giờ lấy từ free text của attacker.
    # ==========================================
    run_b_id = f"run-{run_base_id}-b"
    valid_customer_ids = _find_customers_for_tickets(ticket_ids)

    customer_records = []
    for cust_id in valid_customer_ids:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            parent_scopes=("search_docs", "read_customer"),
            expires_at=expires_at,
        )
        read_allowed, read_reason = policy.check(ctx_read)

        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "on_behalf_of": principal_id,
                "agent_id": "lab24-agent",
                "run_id": run_b_id,
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": cust_id}),
                "classification": "restricted",
                "decision": "allow" if read_allowed else "deny",
                "reason": read_reason,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if read_allowed:
            try:
                rec = tools.read_customer(cust_id)
                customer_records.append(rec)
            except tools.ToolError:
                pass

    # ==========================================
    # Policy Enforcement Point: Chặn egress (http_post)
    # Kể cả khi có chỉ thị injection yêu cầu gửi dữ liệu ra ngoài
    # ==========================================
    if injected is not None:
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer", "http_post"),
            parent_scopes=("search_docs", "read_customer", "http_post"),
            expires_at=expires_at,
        )
        post_allowed, post_reason = policy.check(ctx_post)

        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "on_behalf_of": principal_id,
                "agent_id": "lab24-agent",
                "run_id": run_b_id,
                "tool": "http_post",
                "args_hash": _hash_args({"url": injected.target_url}),
                "classification": "restricted",
                "decision": "allow" if post_allowed else "deny",
                "reason": post_reason,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if post_allowed:
            tools.http_post(injected.target_url, {"records": customer_records})

    return llm.summarize(docs)
