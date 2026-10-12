# Secret giả trong lịch sử Git — Báo cáo Checkpoint 4

- **Scanner và phiên bản:** Gitleaks v8.30.1 (`gitleaks version: 8.30.1`).
- **Commit chứa token giả:** `1bdd849` (full hash: `1bdd849922156c868a5ee9293d68f5b72e242d2c`), commit message: *"chore: seed student lab with synthetic secret exercise"*.
- **File, rule và kết quả quét lịch sử:**
  - File phát hiện: `lab-fake-secret.txt` (dòng 1).
  - Rule ID bắt token: `lab24-synthetic-token`.
  - Chuỗi vi phạm (redacted): `LAB24_FAKE_TOKEN=LAB24-DEMO-****************`.
  - Kết quả quét lịch sử Git (`gitleaks git --config .gitleaks.toml --redact --verbose .`): Phát hiện đúng 1 finding tại commit `1bdd849`.
- **Kết quả quét file hiện tại:**
  - Lệnh: `gitleaks dir --config .gitleaks.toml .`
  - Kết quả: `no leaks found` (0 leaks, sạch hoàn toàn trên mã nguồn hiện tại).
  - Hook pre-commit: `pre-commit run --all-files` đạt trạng thái `Passed`.
- **Nếu đây là credential thật, cần xử lý thế nào:**
  - Ngay lập tức thực hiện **thu hồi (revoke) và rotate** secret tại nhà cung cấp dịch vụ hoặc hệ thống xác thực đích (IDP, cloud provider, API gateway).
  - Kiểm tra audit log của hệ thống để điều tra xem credential bị lộ đã từng được sử dụng để truy cập trái phép hay chưa.
  - Sử dụng công cụ như `git-filter-repo` hoặc BFG Repo-Cleaner để làm sạch lịch sử Git (rewrite history) và force push lại branch sau khi phối hợp với toàn team.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - Git là hệ thống quản lý phiên bản phân tán lưu trữ toàn bộ lịch sử commit. Xoá file ở commit sau (khỏi HEAD) chỉ loại bỏ file khỏi working directory hiện tại; chuỗi dữ liệu nhạy cảm vẫn tồn tại vĩnh viễn trong các object commit cũ của git database (`.git/objects/`) và bất kỳ ai clone repo đều có thể trích xuất ra được bằng `git show 1bdd849` hoặc `git checkout`.
  - Việc pin dependency chỉ bảo vệ tính toàn vẹn của chuỗi cung ứng mã nguồn (software supply chain) trước các cuộc tấn công thay thế package, không thể vô hiệu hóa một credential đã bị lộ ra ngoài. Biện pháp cốt lõi và bắt buộc duy nhất khi credential bị lộ là **rotate / thu hồi** khóa bí mật trên server.
