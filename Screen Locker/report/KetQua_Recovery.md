# Quy trình Recovery — Screen Locker Ransomware

Người thực hiện: Nguyễn Hoàng Khánh Đăng
Ngày: 2026-11-04

## 1. Vấn đề

Máy nạn nhân bị khóa hoàn toàn bởi Screen Locker (Reveton variant):
- Lock screen full-screen, topmost, maximize
- Task Manager bị disable (registry policy)
- Registry Editor bị disable (self-protection)
- Run dialog bị disable
- Explorer.exe bị kill liên tục → mất taskbar
- Tất cả process không phải system bị kill mỗi 800ms

**Không thể recovery trong Normal Mode** vì LockerGuard watchdog kill mọi thứ và re-enforce registry policies.

## 2. Phương pháp: Safe Mode qua Windows Recovery Environment

### Bước 1: Trigger Windows Recovery Environment

Do không thể access bất kỳ giao diện nào trong Normal Mode, sử dụng **force power cycle** 3 lần liên tiếp:

1. Hard shutdown VM (tắt nguồn khi đang boot)
2. Power on → đợi Windows bắt đầu load → hard shutdown lại
3. Lặp lại lần 3

Windows detect 3 lần boot thất bại liên tiếp → tự động vào **Automatic Repair** screen.

### Bước 2: Navigate đến Safe Mode

```
Automatic Repair → Advanced options → Troubleshoot → Advanced options → Startup Settings → Restart
```

Sau khi restart, nhấn **F4** hoặc phím **4** để chọn **Enable Safe Mode**.

**Tại sao Safe Mode hoạt động:** Startup folder items (`runctf.lnk`, `ctfmon32.lnk`) không được thực thi trong Safe Mode. Do đó, cả DLL payload lẫn LockerGuard đều không chạy.

### Bước 3: Xóa file persistence

Mở **Command Prompt (Admin)**:

```cmd
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\runctf.lnk"
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\ctfmon32.lnk"
del "%APPDATA%\{id}.js"
del "%APPDATA%\{id}.pad"
del "%LOCALAPPDATA%\Temp\{id}.dll"
del "%LOCALAPPDATA%\Temp\{id}_guard.exe"
```

Thay `{id}` bằng random hex ID tìm được trong bước điều tra (ví dụ: `c2d911bdae60`).

### Bước 4: Fix registry

**Vấn đề:** `reg.exe` và `regedit` bị block bởi `DisableRegistryTools` policy — ngay cả trong Safe Mode.

**Giải pháp:** Dùng PowerShell (Admin) — PowerShell sử dụng .NET Registry API, bypass `DisableRegistryTools`:

```powershell
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Recurse -Force
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Recurse -Force
```

### Bước 5: Restart và verify

```cmd
shutdown /r /t 0
```

**Verify sau khi restart:**
- [x] Desktop và taskbar hiển thị bình thường
- [x] Task Manager mở được (Ctrl+Shift+Esc)
- [x] Registry Editor mở được (Win+R → regedit)
- [x] Run dialog mở được (Win+R)
- [x] Không còn lock screen
- [x] Windows Defender hoạt động trở lại

## 3. Bài học

| Phát hiện | Ý nghĩa |
|-----------|---------|
| `DisableRegistryTools` block `reg.exe` nhưng không block PowerShell | Nhiều lớp API trong Windows; policy chỉ ảnh hưởng lớp cao (Win32 Registry API) nhưng không ảnh hưởng lớp thấp (.NET) |
| Force power cycle 3 lần → Windows RE | Cơ chế recovery tích hợp của Windows; không cần USB boot hay đĩa cài |
| Safe Mode skip Startup items | Đây là điểm yếu chính của persistence qua Startup folder; ransomware nâng cao hơn dùng Services hoặc Scheduled Tasks để survive cả Safe Mode |
| Hard shutdown → registry không flush | Bằng chứng volatile: cần memory dump để capture đầy đủ. Disk forensics đơn thuần có thể miss registry artifacts |

## 4. So sánh với Reveton thật

| Đặc điểm | Reveton thật | Demo lab |
|-----------|-------------|----------|
| Persistence | Startup folder + Registry Run key | Startup folder (2 .lnk files) |
| Lock mechanism | Custom window + disable Task Manager | rundll32 DLL + LockerGuard kill loop |
| Self-protection | Disable regedit | DisableRegistryTools + DisableTaskMgr + NoRun + kill processes |
| Defender evasion | Polymorphic packing | Add-MpExclusion + registry policies |
| C2 communication | HTTP to C2 server | Simulated (.pad config file) |
| Recovery | Safe Mode + remove files/registry | Safe Mode + remove files/registry (identical) |
