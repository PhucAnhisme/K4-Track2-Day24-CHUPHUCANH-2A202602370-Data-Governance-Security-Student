"""BƯỚC 3d — audit ledger append-only, tamper-evident.

Interface bắt buộc:
    append(entry: dict, path: pathlib.Path) -> dict
    verify(path: pathlib.Path) -> bool
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(data: dict) -> str:
    """Tính SHA-256 từ dict (đã loại bỏ field 'hash' nếu có), sort_keys=True."""
    payload = {k: v for k, v in data.items() if k != "hash"}
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Ghi thêm một bản ghi vào ledger với hash chain bảo vệ toàn vẹn."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists():
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            try:
                last_entry = json.loads(lines[-1])
                prev_hash = last_entry.get("hash", "0" * 64)
            except Exception:
                pass

    record = dict(entry)
    record["prev_hash"] = prev_hash
    record["hash"] = _compute_hash(record)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Kiểm tra tính toàn vẹn của audit ledger:

    - Mọi dòng có reason non-empty
    - prev_hash khớp với hash của dòng trước
    - hash của dòng khớp với tính toán lại từ nội dung
    """
    path = Path(path)
    if not path.exists():
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev = "0" * 64
    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # Kiểm tra reason không được rỗng
        reason = entry.get("reason")
        if not reason or not isinstance(reason, str) or not reason.strip():
            return False

        # Kiểm tra prev_hash
        if entry.get("prev_hash") != expected_prev:
            return False

        # Kiểm tra hash
        stored_hash = entry.get("hash")
        computed_hash = _compute_hash(entry)
        if stored_hash != computed_hash:
            return False

        expected_prev = stored_hash

    return True
