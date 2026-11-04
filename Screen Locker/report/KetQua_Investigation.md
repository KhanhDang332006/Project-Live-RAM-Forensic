# Kết quả điều tra Screen Locker Ransomware (Reveton)

Người thực hiện: Nguyễn Hoàng Khánh Đăng
Ngày: 2026-11-04

## 1. Tổng quan

Máy nạn nhân (WIN10-LOCKER-LAB, Windows 10 Build 19045) bị nhiễm mẫu screen locker mô phỏng cơ chế của Reveton. Hệ thống bị khóa hoàn toàn: lock screen toàn màn hình, không thể mở Task Manager, Registry Editor hoặc Run dialog. Explorer.exe bị kill — không có taskbar hay desktop.

**Phương pháp điều tra:** Clone ổ đĩa nạn nhân (snapshot delta → flat vmdk), mount read-only trên Kali Investigator (chế độ `independent-nonpersistent`), phân tích offline bằng Sleuthkit + RegRipper + chntpw.

## 2. Bằng chứng file (File Artifacts)

### 2.1. Startup folder — Cơ chế persistence

| # | File | Đường dẫn | Mô tả |
|---|------|-----------|-------|
| 1 | `runctf.lnk` | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` | Shortcut chạy DLL payload qua `rundll32.exe` khi đăng nhập |
| 2 | `ctfmon32.lnk` | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` | Shortcut chạy LockerGuard watchdog khi đăng nhập |

**Phân tích:** Hai file `.lnk` trong Startup folder đảm bảo malware tự khởi động lại sau mỗi lần reboot. Tên `runctf` và `ctfmon32` được ngụy trang giống tiến trình hệ thống hợp pháp (CTF Loader, ctfmon).

### 2.2. AppData — Config và loader

| # | File | Đường dẫn | Kích thước | Mô tả |
|---|------|-----------|------------|-------|
| 3 | `{id}.pad` | `%APPDATA%\` | 512 bytes | File config, header "RVTN" (4 bytes) + random data |
| 4 | `{id}.js` | `%APPDATA%\` | ~150 bytes | JScript loader — gọi `rundll32.exe` với DLL payload |

**Phân tích .pad:** 4 byte đầu là `52 56 54 4E` ("RVTN") — signature của Reveton config. Phần còn lại là dữ liệu ngẫu nhiên mô phỏng thông tin C2, unlock code, và cấu hình hiển thị.

**Phân tích .js:** Script JScript sử dụng `WScript.Shell` COM object để thực thi `rundll32.exe` với DLL payload. Đây là lớp persistence thứ hai — nếu `.lnk` bị xóa, `.js` vẫn có thể được gọi thủ công.

### 2.3. Temp — Payload và watchdog

| # | File | Đường dẫn | Mô tả |
|---|------|-----------|-------|
| 5 | `{id}.dll` | `%LOCALAPPDATA%\Temp\` | DLL payload — hiển thị lock screen qua `rundll32.exe` |
| 6 | `{id}_guard.exe` | `%LOCALAPPDATA%\Temp\` | LockerGuard watchdog — kill processes, enforce policies |

**Phân tích _guard.exe:** Binary .NET 32-bit, chạy vòng lặp vô hạn mỗi 800ms:
- Kill tất cả process không phải system-critical (bao gồm explorer.exe)
- Force lock screen window lên topmost + maximize
- Respawn rundll32 nếu bị kill
- Re-enforce registry policies (DisableTaskMgr, DisableRegistryTools, NoRun)

## 3. Bằng chứng registry (Registry Artifacts)

### 3.1. HKCU Policies (LockerGuard enforcement)

| Key | Value | Data | Tác dụng |
|-----|-------|------|----------|
| `HKCU\...\Policies\System` | `DisableTaskMgr` | `1` (DWORD) | Chặn mở Task Manager |
| `HKCU\...\Policies\System` | `DisableRegistryTools` | `1` (DWORD) | Chặn regedit + reg.exe (self-protection) |
| `HKCU\...\Policies\Explorer` | `NoRun` | `1` (DWORD) | Chặn Run dialog (Win+R) |

**Lưu ý forensic quan trọng:** Các key HKCU Policies **không tìm thấy** trong NTUSER.DAT trên disk. Nguyên nhân: VM bị hard-shutdown (tắt nguồn đột ngột) nên registry chưa kịp flush từ memory ra file hive. LockerGuard re-enforce policies mỗi 800ms trong RAM nhưng Windows chỉ flush registry hive định kỳ hoặc khi graceful shutdown. Đây là một **hạn chế forensic thực tế** — bằng chứng chỉ tồn tại trong volatile memory.

### 3.2. HKLM Defender Policies (Dropper)

| Key | Value | Data |
|-----|-------|------|
| `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` | `DisableAntiSpyware` | `1` |
| `HKLM\...\Real-Time Protection` | `DisableRealtimeMonitoring` | `1` |
| `HKLM\...\Real-Time Protection` | `DisableBehaviorMonitoring` | `1` |
| `HKLM\...\Real-Time Protection` | `DisableOnAccessProtection` | `1` |

**Phân tích:** Dropper tự vô hiệu hóa Windows Defender trước khi drop payload, sử dụng 3 phương pháp:
1. `Add-MpExclusion -Path 'C:\'` — thêm exclusion cho toàn bộ ổ C
2. `Set-MpPreference -DisableRealtimeMonitoring $true` — tắt real-time monitoring
3. Group Policy registry keys — backup method qua HKLM

## 4. Timeline sự cố

| Thời điểm | Sự kiện |
|-----------|---------|
| T+0s | Nạn nhân thực thi `RevetonDropper.exe sample.dll` |
| T+1s | Defender bị vô hiệu hóa (exclusion + registry) |
| T+2s | DLL copied → %TEMP%, .pad + .js dropped → %APPDATA% |
| T+3s | runctf.lnk + ctfmon32.lnk created in Startup |
| T+3s | LockerGuard.exe deployed → %TEMP% |
| T+4s | Registry lockdown set (DisableTaskMgr, DisableRegistryTools, NoRun) |
| T+5s | rundll32.exe launched with DLL → lock screen hiển thị |
| T+5s | LockerGuard.exe launched hidden → bắt đầu kill loop |
| T+6s | Explorer.exe bị kill → mất taskbar, desktop icons |
| Reboot | runctf.lnk + ctfmon32.lnk tự động chạy lại → lock screen persistent |

## 5. Phát hiện quan trọng

1. **Self-protection qua DisableRegistryTools:** Malware tạo catch-22 — admin không thể dùng `reg.exe` hoặc `regedit` để xóa chính policy `DisableRegistryTools`. Phải dùng PowerShell .NET Registry API để bypass.

2. **Volatile registry evidence:** Hard shutdown khiến HKCU policies không flush ra NTUSER.DAT. Trong điều tra thực tế, cần kết hợp memory forensics (RAM dump) để tìm được bằng chứng registry đầy đủ.

3. **Process kill loop:** LockerGuard kill tất cả process không phải system-critical mỗi 800ms, bao gồm explorer.exe. Điều này khiến nạn nhân không thể: mở Task Manager, sử dụng taskbar, chuyển tab, hoặc mở bất kỳ ứng dụng nào.

4. **Safe Mode as recovery vector:** Startup items không chạy trong Safe Mode, nên cả runctf.lnk và ctfmon32.lnk đều bị bỏ qua. Đây là điểm yếu duy nhất của cơ chế persistence.
