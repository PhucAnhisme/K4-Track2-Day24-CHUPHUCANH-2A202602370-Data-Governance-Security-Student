# Baseline — Điền trong Checkpoint 1

1. **Agent có identity mỗi run chưa? Dẫn file/hàm:**
   - **Chưa.** Trong `agent/loop.py` tại hàm `_naive_loop(message: str, llm)` (dòng 27–55), luồng xử lý không định danh `principal_id`, không sinh `run_id`, không gắn context danh tính hay phạm vi quyền hạn (scopes). Mọi hành động được thực thi với toàn quyền của tiến trình hệ thống mà không phân biệt người dùng.

2. **Ai cho phép `http_post`? Dẫn file/hàm:**
   - **Không có cơ chế kiểm soát (không có PEP).** Quyết định gọi `http_post` hoàn toàn do chỉ thị của kẻ tấn công dẫn dắt. Tại `agent/loop.py` (dòng 34–44), khi `injected = llm.find_injection(...)` trả về kết quả, hàm `_naive_loop` trực tiếp thực thi `tools.http_post(injected.target_url, {"records": collected})` (dòng 44) tới bất kỳ endpoint nào kẻ tấn công chỉ định (chỉ bị giới hạn bởi hardcode allowlist port `10024` trong `agent/tools.py::http_post` dòng 76–84).

3. **Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:**
   - **Bằng chứng chỉ nằm ở phía server nhận (sink), agent không có bằng chứng nội bộ.** Dữ liệu bị rò rỉ chỉ được ghi nhận thụ động tại `reports/sink.log` do server ngoài ghi nhận qua hàm `do_POST()` trong `sink/sink.py` (dòng 52–63). Tại phía agent, không có hệ thống audit ledger nào lưu lại dấu vết tool call, tham số hay lý do cấp phép.
