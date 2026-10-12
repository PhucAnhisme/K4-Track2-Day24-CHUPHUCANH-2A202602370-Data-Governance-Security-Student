"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Interface bắt buộc:
    detect(text: str) -> list[dict]
    redact(text: str) -> str
"""
from __future__ import annotations

import re


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL.
    
    Trả về list[{"type": str, "start": int, "end": int}] sắp xếp theo start offset.
    """
    entities: list[dict] = []
    occupied: set[int] = set()

    # 1. Email: chuẩn local@domain.tld
    for m in re.finditer(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text):
        s, e = m.start(), m.end()
        entities.append({"type": "EMAIL", "start": s, "end": e})
        occupied.update(range(s, e))

    # 2. VN_BANK_ACCOUNT: đi kèm với từ khoá STK / số tài khoản / tài khoản
    for m in re.finditer(r"(?i)(?:STK|số tài khoản|tài khoản)\s*[:.]?\s*(\d{8,16})(?!\d)", text):
        s, e = m.start(1), m.end(1)
        if not any(i in occupied for i in range(s, e)):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": s, "end": e})
            occupied.update(range(s, e))

    # 3. VN_CCCD: 12 chữ số liên tiếp
    for m in re.finditer(r"(?<!\d)\d{12}(?!\d)", text):
        s, e = m.start(), m.end()
        if not any(i in occupied for i in range(s, e)):
            entities.append({"type": "VN_CCCD", "start": s, "end": e})
            occupied.update(range(s, e))

    # 4. VN_PHONE: 10 chữ số bắt đầu bằng 0 hoặc +84
    for m in re.finditer(r"(?<!\d)(?:0\d{9}|\+84\d{9})(?!\d)", text):
        s, e = m.start(), m.end()
        if not any(i in occupied for i in range(s, e)):
            entities.append({"type": "VN_PHONE", "start": s, "end": e})
            occupied.update(range(s, e))

    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế mọi thực thể PII tìm thấy bằng [REDACTED_<TYPE>]."""
    entities = detect(text)
    # Thay từ cuối về đầu để không làm lệch offset
    sorted_entities = sorted(entities, key=lambda x: x["start"], reverse=True)
    res = text
    for ent in sorted_entities:
        res = res[:ent["start"]] + f"[REDACTED_{ent['type']}]" + res[ent["end"]:]
    return res
