# Screen Locker Demo

Kịch bản demo điều tra **Screen Locker Ransomware** — mã độc khóa màn hình, vô hiệu hóa giao diện người dùng, chặn Task Manager và tự bảo vệ khỏi bị gỡ bỏ.

Mẫu mô phỏng: **Reveton** (Win32/Reveton, Trojan.Ransomlock) — một trong những screen locker phổ biến nhất giai đoạn 2012–2014, giả mạo cảnh báo từ cơ quan pháp luật (FBI, Interpol) để đòi tiền chuộc.

## Pipeline demo

```
build_and_deploy.ps1          ← Compile source, tạo ISO, deploy vào VM
        │
        ▼
VM: RevetonDropper.exe         ← Lây nhiễm: drop 6 file + 4 registry + lock screen
        │
        ▼
vmware-vdiskmanager            ← Clone ổ đĩa → evidence image (write-protected)
        │
        ▼
Kali: investigate.sh           ← Điều tra offline: tìm artifacts trên disk + registry
        │
        ▼
VM: recover_safemode.bat       ← Recovery: Safe Mode → xóa file + fix registry
```

## Cấu trúc thư mục

```
Screen Locker/
├── README.md
├── tools/
│   ├── build_and_deploy.ps1   # Compile, tạo ISO, deploy vào VM qua SATA CD-ROM
│   ├── investigate.sh         # Script điều tra tự động trên Kali (chạy trên evidence disk)
│   └── recover_safemode.bat   # Script recovery trong Safe Mode (chạy trong VM)
├── samples/
│   └── src/
│       ├── RevetonDropper.cs  # Source code dropper (C#, .NET 4.0, x86)
│       └── LockerGuard.cs     # Source code watchdog (C#, .NET 4.0, x86)
└── report/
    ├── KetQua_Investigation.md  # Kết quả điều tra (artifacts + timeline)
    └── KetQua_Recovery.md       # Quy trình và kết quả recovery
```

**Thư mục payload bên ngoài repo** (không đưa lên git):

```
D:\DoAnDigitalForensic\ScreenLocker-Payload\
├── sample.dll                 # DLL payload (user tải từ MalwareBazaar)
├── RevetonDropper.exe         # Compiled dropper (output của build_and_deploy.ps1)
├── LockerGuard.exe            # Compiled guard (output của build_and_deploy.ps1)
└── deploy.iso                 # ISO chứa cả 3 file trên (output của build_and_deploy.ps1)
```

## Cơ chế hoạt động

### Dropper (RevetonDropper.exe)

| Bước | Hành động | Artifact |
|------|-----------|----------|
| 0 | Vô hiệu hóa Windows Defender (exclusion + registry policies) | HKLM Defender keys |
| 1 | Copy DLL payload → `%TEMP%\{id}.dll` | File |
| 2 | Drop config → `%APPDATA%\{id}.pad` (header "RVTN") | File |
| 3 | Drop JS loader → `%APPDATA%\{id}.js` | File |
| 4 | Tạo `runctf.lnk` trong Startup (chạy DLL qua rundll32) | File + Persistence |
| 5 | Deploy LockerGuard → `%TEMP%\{id}_guard.exe` + `ctfmon32.lnk` trong Startup | File + Persistence |
| 6 | Set registry lockdown: DisableTaskMgr, DisableRegistryTools, NoRun | Registry |
| 7 | Launch DLL payload + guard (hidden) | Process |

### LockerGuard (watchdog)

Vòng lặp mỗi 800ms:
1. **Kill processes** — Tất cả process không phải system-critical bị kill, bao gồm explorer.exe (mất taskbar)
2. **Force topmost** — Lock screen window luôn ở trên cùng, maximize
3. **Respawn payload** — Nếu rundll32 bị kill, tự khởi động lại
4. **Re-enforce registry** — Ghi lại DisableTaskMgr, DisableRegistryTools, NoRun mỗi chu kỳ

### Tại sao cần Safe Mode để recovery

- LockerGuard kill mọi process không phải system → không thể mở CMD/PowerShell
- DisableTaskMgr chặn Task Manager → không thể kill LockerGuard
- DisableRegistryTools chặn reg.exe/regedit → không thể sửa registry
- Catch-22: cần sửa registry để dùng reg.exe, nhưng reg.exe bị chặn bởi registry

**Safe Mode** bỏ qua Startup folder → LockerGuard không chạy → có thể dùng PowerShell để fix registry (PowerShell dùng .NET API, bypass DisableRegistryTools).

## Sử dụng

### Chuẩn bị

```
pip install pycdlib
```

Tải sample.dll từ MalwareBazaar (hoặc bất kỳ DLL nào có export `DllMain`) và đặt vào `ScreenLocker-Payload/`.

### Build & Deploy

```powershell
.\tools\build_and_deploy.ps1 -PayloadDir D:\DoAnDigitalForensic\ScreenLocker-Payload
```

Script sẽ:
1. Compile `RevetonDropper.cs` + `LockerGuard.cs` (32-bit, .NET 4.0)
2. Tạo ISO chứa 3 file (dropper + guard + sample.dll)
3. Gắn ISO vào VM qua SATA CD-ROM
4. Start VM

Trong VM: copy file từ CD-ROM ra Desktop → chạy Admin → `RevetonDropper.exe sample.dll`.

### Điều tra (trên Kali)

```bash
# Mount evidence disk (đã gắn read-only trong VMware)
sudo mount -o ro,noexec /dev/sdb1 /mnt/evidence

# Chạy script điều tra
sudo ./tools/investigate.sh /mnt/evidence ./output
```

### Recovery (trong Safe Mode)

```
# Trigger Windows RE: force power cycle 3 lần
# → Troubleshoot → Advanced Options → Startup Settings → F4 (Safe Mode)
# → Chạy CMD Admin:

recover_safemode.bat
```

## Bằng chứng dự kiến

### File artifacts (6 files)

| # | File | Vị trí | Nhận dạng |
|---|------|--------|-----------|
| 1 | `{id}.dll` | `%TEMP%` | DLL payload, SHA-256 match MalwareBazaar |
| 2 | `{id}.pad` | `%APPDATA%` | Header 4 bytes = `52 56 54 4E` ("RVTN") |
| 3 | `{id}.js` | `%APPDATA%` | Chứa "rundll32" + đường dẫn DLL |
| 4 | `runctf.lnk` | Startup folder | Shortcut → rundll32.exe + DLL |
| 5 | `ctfmon32.lnk` | Startup folder | Shortcut → LockerGuard.exe |
| 6 | `{id}_guard.exe` | `%TEMP%` | .NET binary, ~7KB |

### Registry artifacts (4 policies)

| # | Key | Value | Tác dụng |
|---|-----|-------|----------|
| 1 | `HKCU\...\Policies\System` | `DisableTaskMgr=1` | Chặn Task Manager |
| 2 | `HKCU\...\Policies\System` | `DisableRegistryTools=1` | Self-protection |
| 3 | `HKCU\...\Policies\Explorer` | `NoRun=1` | Chặn Run dialog |
| 4 | `HKLM\...\Windows Defender` | `DisableAntiSpyware=1` | Tắt Defender |

**Lưu ý:** HKCU policies có thể **không xuất hiện** trong NTUSER.DAT nếu VM bị hard-shutdown (registry chưa flush). Đây là hạn chế forensic thực tế — cần kết hợp memory forensics.

## Quy tắc an toàn

- Mẫu ransomware **chỉ chạy trong máy ảo cô lập** (không mạng, không clipboard, không USB)
- File `.exe`, `.dll`, `.iso` **không đưa lên repo** (đã chặn trong `.gitignore`)
- Snapshot VM trước và sau mỗi bước demo
- Evidence disk luôn mount `independent-nonpersistent` (write-protected)
