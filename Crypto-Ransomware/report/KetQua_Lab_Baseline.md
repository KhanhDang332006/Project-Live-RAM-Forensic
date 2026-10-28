# Kết quả – Dựng lab cô lập (H1) và dump baseline (H3)

**Người làm:** Minh Hoàng. **Ngày:** 15/10/2026.
Mục tiêu: có môi trường để chạy mẫu ransomware mà không ra ngoài, và có danh sách khóa AES "nền" của
Windows sạch để loại ra khi dò khóa trên dump lúc nhiễm.

## 1. Môi trường lab

| Thành phần | Chi tiết |
|---|---|
| Phần mềm ảo hóa | VMware Workstation (máy thật Windows 11) |
| VM victim | Windows 10 (build 10.0.19045), RAM 4 GB, tên máy `DESKTOP-6H0B91O` |
| VM Kali | Kali Linux, chạy INetSim, tcpdump, Volatility 3 (venv `~/dfir-venv`), `keyscan`, `aeskeyfind` |
| Mạng cô lập | LAN Segment `malware-lab`, subnet `10.10.10.0/24`, không có DHCP |
| IP victim | `10.10.10.10/24`, gateway `10.10.10.1`, DNS `10.10.10.1` (tĩnh) |
| IP Kali (card LAN segment) | `10.10.10.1/24` |

Victim chỉ có **một** card mạng, nối vào LAN segment, nên không có đường ra Internet. Mọi truy cập mạng của
victim (gateway, DNS) đều đi về Kali. Kali còn thêm một card NAT riêng để cài gói; card này ngắt khi chạy mẫu.

Các đường nối giữa victim và máy thật đã tắt: Shared Folders = Disabled, drag-and-drop và copy-paste tắt.
Dump RAM luôn lấy từ máy thật bằng chức năng của VMware (Suspend/Snapshot), không chạy công cụ chụp RAM
bên trong victim (giữ đúng cách chụp qua hypervisor mà bài báo mô tả).

### 1.1. Dịch vụ giả lập trên Kali

- **INetSim 1.3.2**, bind vào `10.10.10.1`: giả lập HTTP, HTTPS, SMTP, FTP, ... để mẫu nào gọi ra ngoài cũng
  nhận được phản hồi giả, không ra Internet thật.
- **tcpdump** bắt gói trên card LAN segment, ghi ra `~/pcap/*.pcap` (nguồn cho phân tích mạng, việc D6 của Đăng).

Vì sao không cắt mạng hẳn: nhiều ransomware kiểm tra kết nối hoặc gọi C2 trước khi mã hóa; nếu không có phản hồi
có thể dừng sớm hoặc chạy khác đi. Giả lập dịch vụ vừa giữ cho mẫu chạy tự nhiên vừa thu được dấu vết mạng.

### 1.2. Sự cố: dịch vụ DNS của INetSim không hoạt động

Triệu chứng: `nslookup` trên victim báo timeout, `curl http://10.10.10.1` thì ra đúng trang mặc định của
INetSim (HTTP chạy), nhưng `curl http://example.com` lỗi `Could not resolve host`. `ss -ulnp | grep :53` trên
Kali không thấy cổng 53; trong pcap chụp lúc đó, mọi truy vấn DNS nhận lại `ICMP udp port 53 unreachable`.
Khi khởi động INetSim có dòng `Attempt to start Net::DNS::Nameserver in a subprocess`.

Nguyên nhân (đã xác định trong mã nguồn): thư viện Perl `Net::DNS` bản **1.54** (mới) kiểm tra, ở dòng 553 file
`/usr/share/perl5/Net/DNS/Nameserver.pm`:

```perl
croak 'Attempt to start ', ref($self), ' in a subprocess' unless $$ == $pid;
```

INetSim 1.3.2 (bản 2020) tạo đối tượng server ở tiến trình cha rồi fork tiến trình con để chạy, nên PID lệch
và dịch vụ DNS chết ngay sau khi báo `started`. Đây là lỗi tương thích phiên bản giữa INetSim cũ và `Net::DNS` mới.

Cách xử lý (chỉ trên Kali lab, có sao lưu file gốc): vô hiệu hóa dòng kiểm tra đó.

```bash
sudo cp /usr/share/perl5/Net/DNS/Nameserver.pm /usr/share/perl5/Net/DNS/Nameserver.pm.bak
sudo sed -i '553s/^/#/' /usr/share/perl5/Net/DNS/Nameserver.pm
```

Sau đó khởi động lại INetSim thì DNS hoạt động. Lưu ý: nếu `apt upgrade` cập nhật gói `libnet-dns-perl` thì file bị
ghi đè và phải sửa lại. Muốn hoàn tác: chép lại file `.bak`.

### 1.3. Kiểm tra cô lập

| Kiểm tra trên victim | Kết quả đúng | Trạng thái |
|---|---|---|
| `ping 10.10.10.1` | Có trả lời (thấy Kali) | Đạt |
| `ping 8.8.8.8` | Thất bại (không ra Internet) | Đạt |
| `nslookup example.com` | Trả về `10.10.10.1` | Đạt sau khi sửa DNS (mục 1.2) |
| `curl http://10.10.10.1` | Trang "INetSim default HTML page" | Đạt |
| `ipconfig /all` | Một card, IP `10.10.10.10`, DNS `10.10.10.1` | Đạt |

(Kết quả `ping`, `nslookup` sau khi sửa DNS do Hoàng xác nhận trực tiếp; riêng `curl` và `ipconfig` đã lưu output.)

Ghi chú về pcap: file `test.pcap` đầu tiên bắt **trước khi** sửa DNS, nên chỉ thấy truy vấn DNS của Windows
(`g.live.com`, `settings-win.data.microsoft.com`, `ctldl.windowsupdate.com`, ...) kèm phản hồi
`udp port 53 unreachable`. Đây là lưu lượng nền của Windows 10, bình thường; khi phân tích mẫu thật cần lọc ra.

## 2. Chuẩn bị victim

- **File mồi:** 10 file từ `samples/plain/` (pdf, doc, docx, xls, xlsx, txt, jpg, csv, zip) chép vào
  `C:\Users\<user>\Documents\CongTy\`. Đặt trong Documents để giống tài liệu người dùng thật, nơi ransomware
  thường nhắm tới. Hash gốc của từng file nằm trong `manifest.csv` (làm bằng `make_manifest.py`).
- **Audit tạo tiến trình:** bật để Event Log ghi sự kiện **4688** (tiến trình mới, kèm dòng lệnh). Dữ liệu này
  giúp xác định mẫu chạy lúc nào, bằng lệnh gì (việc D5 của Đăng).

  ```
  auditpol /set /subcategory:"Process Creation" /success:enable
  reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
  ```
  Kiểm tra lại bằng `auditpol /get /subcategory:"Process Creation"` cho kết quả `Success`.
- **Snapshot sạch** tên `clean-baseline`: trạng thái gốc để quay về sau mỗi lần chạy mẫu.

## 3. Dump baseline (H3)

### 3.1. Cách làm

Snapshot `clean-baseline` được chụp khi victim đang chạy (không suspend), nên VMware ghi luôn RAM tại thời điểm đó:

| File | Vai trò |
|---|---|
| `Win10-VICTIM-Snapshot1.vmem` | RAM thô, 4 294 967 296 byte (4 GiB) |
| `Win10-VICTIM-Snapshot1.vmsn` | Metadata của snapshot (Volatility cần file này đặt cùng tên, cùng thư mục với `.vmem`) |

Hai file này copy sang Kali bằng shared folder (bật cho Kali, victim vẫn tắt), rồi chạy:

```bash
cd ~/Downloads/baseline
time ../keyscan Win10-VICTIM-Snapshot1.vmem --out keys_baseline.json
```

Trong thư mục VM còn có cặp `Win10-VICTIM-49c98f1c.vmem` và `.vmss` là RAM đang chạy / trạng thái suspend; hai file
đó không dùng cho baseline.

### 3.2. Kết quả

| Mục | Giá trị |
|---|---|
| Dung lượng quét | 4 294 967 296 byte (cả RAM victim) |
| Thời gian | **52,57 s** (bản C++, bộ lọc Shannon mặc định, cả 3 độ dài khóa) |
| Số khóa tìm được | **149** khóa AES |
| Phân bố | 9 khóa 128-bit, 140 khóa 256-bit, 0 khóa 192-bit (đếm từ output) |
| File kết quả | `keys_baseline.json` |

Nhận xét:
- Windows sạch, chưa chạy thêm chương trình nào, vẫn giữ **149 key schedule AES** hợp lệ trong RAM. Nghĩa là
  nếu quét cả dump mà không loại khóa nền thì ứng viên ra cả trăm cái, không phải vài cái như lúc quét riêng
  tiến trình keyholder.
- Phần lớn là khóa 256-bit. Chưa xác định được tiến trình hay thành phần nào của Windows sinh ra từng khóa
  (cần đối chiếu offset với vùng nhớ tiến trình); mục đích của baseline chỉ là loại chúng ra, không cần biết nguồn.
- Hai khóa cuối danh sách là `7c3877dc09609d7465536a5a179af0a4` (128-bit, offset `0xfb22c5f0`) và
  `738f1529ec0cd0222ea1fc55dba915c67fe5427c04c418b5afc9beb64b5fa469` (256-bit, offset `0xfb3b6ba0`).
  Đây **chính là hai khóa "phụ"** xuất hiện khi dò dump tiến trình `python.exe` trong thí nghiệm keyholder
  (xem [KetQua_Part1.md](KetQua_Part1.md)). Nay xác nhận chúng là khóa có sẵn của Windows, có mặt trước khi
  chạy keyholder, chứ không liên quan đến chương trình test.
- Hai khóa keyholder (`e71dcd19…` AES-128, `5477e858…` AES-256) **không** có trong baseline, đúng kỳ vọng
  vì chúng chỉ xuất hiện sau khi chạy keyholder.
- 4 GiB RAM quét trong ~53 s nghĩa là tốc độ cỡ 80 MB/s với 3 độ dài khóa, đủ nhanh để quét nhiều dump liên tiếp
  cho Part 2.

### 3.3. Cách dùng baseline khi dò khóa

```bash
../keyscan <dump_khi_nhiem>.vmem --baseline Win10-VICTIM-Snapshot1.vmem --out keys.json
```

`keyscan` quét lại file baseline mỗi lần chạy (mất thêm khoảng 53 s) rồi bỏ các khóa trùng. Với RAM 4 GB, một lần
dò có baseline mất khoảng 2 phút.

Giới hạn cần ghi nhận:
- Khóa nền không cố định: khóa phiên TLS, khóa của tiến trình mới sinh ra theo thời gian. Khóa lạ sau khi nhiễm
  **không chắc** là khóa của ransomware. Baseline chỉ loại được những khóa đã có lúc sạch.
- Baseline chụp ở trạng thái "vừa boot, chưa làm gì"; càng giống trạng thái lúc chạy mẫu thì loại càng nhiều khóa nền.

## 4. Phương án lấy khóa "sạch và chuẩn" khi chạy mẫu thật

Ba lớp lọc, từ thô đến chính xác:

| Lớp | Cách làm | Kết quả |
|---|---|---|
| 1. Quét theo tiến trình | Volatility tìm PID ransomware (`windows.pstree`, `cmdline`), `windows.memmap --pid --dump`, chạy keyscan trên file đó (RansomAES của bài báo cũng quét theo `-p <pid>`) | Từ ~150 khóa xuống còn vài khóa |
| 2. Loại khóa nền | `keyscan --baseline` với dump baseline ở mục 3 | Bỏ khóa Windows có sẵn |
| 3. Thử giải mã | `decrypt.py` thử từng khóa lên file `.locked`, so SHA-256 với `manifest.csv` | Còn đúng 1 khóa; đây là bằng chứng khóa đúng |

Cách chọn:
- Biết tiến trình ransomware: lớp 1 + 3 là đủ.
- Mẫu inject vào tiến trình khác, hoặc sinh nhiều tiến trình con: quét nguyên dump rồi dùng lớp 2, sau đó lớp 3.
- Part 2 (timeline khóa): thêm cách so hai dump liên tiếp, khóa có ở dump sau mà dump trước chưa có là khóa mới.

Lớp 3 là kiểm chứng duy nhất chắc chắn; lớp 1 và 2 chỉ thu hẹp danh sách.

## 5. Việc còn lại sau phần này

- **H2:** script chụp RAM định kỳ bằng `vmrun`, ghi `capture_log.csv`, test bằng keyholder `--hold`.
- Ghi hash cho `Win10-VICTIM-Snapshot1.vmem`, `.vmsn`, `keys_baseline.json` vào `custody_log.csv`
  (`hash_evidence.py acquire`, việc D2 của Đăng); bằng chứng nằm trên máy, không đưa lên git.
- Chốt mẫu Phobos (C1), chạy mẫu (C2), rồi H4, H5, H6.
- Đo lại `aeskeyfind` và `findaes` trên dump nguyên cả máy 4 GB để có số so sánh công cụ ở quy mô thật.
