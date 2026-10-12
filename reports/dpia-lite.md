# DPIA-lite — Báo cáo Đánh giá Tác động Quyền riêng tư (Checkpoint 5)

### 1. Loại dữ liệu và phân loại:
- **Dữ liệu công khai / Nội bộ (`internal`):** Nội dung các ticket hỗ trợ khách hàng nằm trong `corpus/*.md` (tiêu đề, nội dung mô tả sự cố, câu hỏi về hoá đơn/khuyến mãi).
- **Dữ liệu nhạy cảm / Hạn chế (`restricted`):** Hồ sơ thông tin định danh cá nhân (PII) trong `data/customers.json`, bao gồm: Họ tên, Số CCCD 12 số, Số điện thoại di động, Số tài khoản ngân hàng (STK), Địa chỉ Email. Toàn bộ là dữ liệu tổng hợp (synthetic), không chứa PII thật.

### 2. Mục đích xử lý và principal:
- **Mục đích hợp lệ (`request_purpose`):**
  - `summarize-tickets`: Tổng hợp các yêu cầu hỗ trợ khách hàng theo tuần.
  - `support-reply`: Tra cứu thông tin khách hàng gắn với ticket cụ thể để phản hồi nghiệp vụ.
  - `privacy-audit`: Kiểm toán tuân thủ bảo vệ dữ liệu.
- **Vai trò chủ thể (`principal_id`):**
  - `support_l1`: Nhân viên hỗ trợ cấp 1, chỉ được phép gọi `search_docs`, bị cấm truy cập hồ sơ khách hàng `read_customer`.
  - `dpo`: Data Protection Officer, có thẩm quyền tra cứu `read_customer` phục vụ giải quyết khiếu nại và kiểm toán.
  - `billing`: Kế toán/đối soát, được tra cứu thông tin khách hàng phục vụ đối soát giao dịch.

### 3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- **Run A (`run-xxxx-a`):** Chỉ gọi công cụ `search_docs` để đọc tài liệu trong `corpus/`. Run A bị cô lập hoàn toàn khỏi kho dữ liệu khách hàng và mạng ngoài (không có `read_customer`, không có `http_post`).
- **Biên giới phân tách (Boundary):** Run A chỉ trích xuất danh sách `ticket_id` dạng số nguyên từ tên file (`ticket-XXX.md`), lọc bỏ toàn bộ free-text và chỉ thị tiêm nhiễm trước khi gửi sang Run B.
- **Run B (`run-xxxx-b`):** Nhận `ticket_id`, đối chiếu ngược với trường `related_tickets` trong `data/customers.json` để xác định đúng khách hàng hợp lệ, sau đó gọi `read_customer` nếu principal có thẩm quyền (như `dpo`).
- **Kênh xuất dữ liệu (Egress endpoint):** Kẻ tấn công cố gắng chuyển hướng dữ liệu tới `http://127.0.0.1:10024/reconcile`. Điểm kiểm soát chính sách (PEP) tại `agent/runner.py` can thiệp và từ chối tool `http_post` trước khi bất kỳ kết nối mạng nào được thiết lập.

### 4. Bằng chứng deny/allow và giới hạn của mock:
- **Bằng chứng Deny/Allow:**
  - `reports/attack-before.log`: Chứa bản ghi PII của `KH-000999` bị rò rỉ trước khi áp dụng kiểm soát kiến trúc.
  - `reports/attack-after.log`: File rỗng (0 bytes), chứng minh không có byte dữ liệu nào bị gửi ra sink sau khi áp dụng kiểm soát.
  - `reports/ledger.jsonl`: Lưu chuỗi hash chain tamper-evident với 23 bản ghi, ghi nhận đầy đủ các lần `allow` hợp lệ cho `search_docs`/`read_customer` của `dpo` và `deny` cho `http_post` với lý do rõ ràng.
- **Giới hạn của Mock:**
  - Mock LLM hoạt động bằng heuristic nhận diện từ khóa/marker tĩnh, giúp kiểm thử có tính lặp lại và tin cậy cao trong phòng lab, nhưng không phản ánh hết sự đa dạng của các kỹ thuật tấn công prompt injection thế hệ mới trên mô hình ngôn ngữ lớn thật (adversarial suffix, jailbreak ngữ cảnh sâu, đa ngôn ngữ).
  - Xác thực người dùng thông qua tham số CLI `--as` chỉ mang tính chất mô phỏng phân quyền trong môi trường giả lập; hệ thống production cần tích hợp cơ chế xác thực danh tính mạnh (JWT/OAuth2/mTLS) và lưu trữ audit log trên hệ thống lưu trữ phân tán WORM.
