# NT334 – Đồ án Pháp chứng Kỹ thuật số: Điều tra Ransomware

Repo tổng hợp mã nguồn, công cụ và kịch bản demo điều tra cho đồ án môn **NT334 – Pháp chứng kỹ thuật số**.

## Các kịch bản demo

Dự án được chia thành 3 kịch bản demo tương ứng trong 3 thư mục:

1. **[Crypto-Ransomware](./Crypto-Ransomware/)**:
   - Tái lập nghiên cứu bài báo của *S. R. Davies et al. (2020)*: Dò tìm khóa AES (128/192/256-bit) trong dump RAM (`.vmem`) khi ransomware đang mã hóa và giải mã khôi phục dữ liệu gốc.
   - Chứa toàn bộ công cụ dò khóa (`keyscan`), giải mã (`decrypt.py`), chuỗi quản lý bằng chứng (chain of custody) và báo cáo thực nghiệm.

2. **[Screen Locker](./Screen%20Locker/)**:
   - Kịch bản demo điều tra các dòng ransomware khóa màn hình (khóa giao diện, can thiệp Winlogon, startup registry, điều tra RAM và trích xuất mã mở khóa).

3. **[RaaS](./RaaS/)**:
   - Kịch bản demo điều tra mô hình Ransomware-as-a-Service (RaaS) và tống tiền kép (double extortion, lưu lượng mạng C2, trích xuất cấu hình và điều tra rò rỉ dữ liệu).

