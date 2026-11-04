# build_and_deploy.ps1 — NT334 Screen Locker Demo
# Compile dropper + guard, package with sample DLL into ISO, deploy to VM via SATA CD-ROM.
#
# Usage:
#   .\tools\build_and_deploy.ps1 -PayloadDir D:\DoAnDigitalForensic\ScreenLocker-Payload
#
# Prerequisites:
#   - sample.dll must be in $PayloadDir (user downloads from MalwareBazaar)
#   - Python 3 with pycdlib installed (pip install pycdlib)
#   - VMware Workstation installed
#
# Steps:
#   1. Compile RevetonDropper.cs and LockerGuard.cs (32-bit, .NET 4.0)
#   2. Create ISO containing: RevetonDropper.exe, LockerGuard.exe, sample.dll
#   3. Attach ISO to victim VM as SATA CD-ROM
#   4. Start VM (user runs dropper manually inside VM)

param(
    [Parameter(Mandatory=$true)]
    [string]$PayloadDir,

    [string]$VmxPath = "D:\VMwareVMs\WIN10-LOCKER-LAB\WIN10-LOCKER-LAB.vmx",
    [string]$SnapshotName = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$srcDir   = Join-Path $PSScriptRoot "..\samples\src"
$csc      = Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe"

Write-Host "=== NT334 Screen Locker — Build & Deploy ===" -ForegroundColor Cyan
Write-Host ""

# --- Validate prerequisites ---
if (-not (Test-Path $csc)) {
    Write-Host "[!] C# compiler not found: $csc" -ForegroundColor Red
    exit 1
}

$sampleDll = Join-Path $PayloadDir "sample.dll"
if (-not (Test-Path $sampleDll)) {
    Write-Host "[!] sample.dll not found in: $PayloadDir" -ForegroundColor Red
    Write-Host "    Download from MalwareBazaar and place it there." -ForegroundColor Yellow
    exit 1
}

# --- Step 1: Compile ---
Write-Host "[*] Step 1 — Compiling source code..." -ForegroundColor Yellow

$dropperCs  = Join-Path $srcDir "RevetonDropper.cs"
$guardCs    = Join-Path $srcDir "LockerGuard.cs"
$dropperExe = Join-Path $PayloadDir "RevetonDropper.exe"
$guardExe   = Join-Path $PayloadDir "LockerGuard.exe"

Write-Host "    Compiling RevetonDropper.cs..."
& $csc /nologo /target:exe /platform:x86 /reference:Microsoft.CSharp.dll /out:$dropperExe $dropperCs
if ($LASTEXITCODE -ne 0) { Write-Host "[!] Dropper compilation failed" -ForegroundColor Red; exit 1 }
Write-Host "    -> $dropperExe ($((Get-Item $dropperExe).Length) bytes)" -ForegroundColor Green

Write-Host "    Compiling LockerGuard.cs..."
& $csc /nologo /target:winexe /platform:x86 /out:$guardExe $guardCs
if ($LASTEXITCODE -ne 0) { Write-Host "[!] Guard compilation failed" -ForegroundColor Red; exit 1 }
Write-Host "    -> $guardExe ($((Get-Item $guardExe).Length) bytes)" -ForegroundColor Green

# --- Step 2: Create ISO ---
Write-Host ""
Write-Host "[*] Step 2 — Creating transfer ISO..." -ForegroundColor Yellow

$isoPath = Join-Path $PayloadDir "deploy.iso"

$pyScript = @"
import pycdlib, sys, os
iso = pycdlib.PyCdlib()
iso.new(interchange_level=1, joliet=3, vol_ident='LOCKER_DEPLOY')
payload_dir = sys.argv[1]
files = ['RevetonDropper.exe', 'LockerGuard.exe', 'sample.dll']
for f in files:
    src = os.path.join(payload_dir, f)
    if not os.path.isfile(src):
        print(f'[!] Missing: {src}')
        sys.exit(1)
    iso_name = f.upper().replace('.', '_') + '.' + f.split('.')[-1].upper() + ';1'
    # Truncate ISO9660 name to 8.3 if needed
    base, ext = os.path.splitext(f)
    short = (base[:8].upper() + ext.upper()).replace(' ', '_')
    iso_path = '/' + short + ';1'
    joliet_path = '/' + f
    iso.add_file(src, iso_path=iso_path, joliet_path=joliet_path)
    sz = os.path.getsize(src)
    print(f'    Added: {f} ({sz} bytes)')
iso.write(sys.argv[2])
iso.close()
print(f'    ISO written: {sys.argv[2]}')
"@

$pyScriptPath = Join-Path $PayloadDir "_make_iso.py"
$pyScript | Out-File -Encoding utf8 $pyScriptPath

python -I $pyScriptPath $PayloadDir $isoPath
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] ISO creation failed. Install pycdlib: pip install pycdlib" -ForegroundColor Red
    exit 1
}
Write-Host "    -> $isoPath ($((Get-Item $isoPath).Length) bytes)" -ForegroundColor Green
Remove-Item $pyScriptPath -Force

# --- Step 3: Snapshot (optional) + Attach ISO ---
Write-Host ""
Write-Host "[*] Step 3 — Attaching ISO to VM..." -ForegroundColor Yellow

# Find vmrun
$vmrun = $null
foreach ($p in @(
    "${env:ProgramFiles}\VMware\VMware Workstation\vmrun.exe",
    "${env:ProgramFiles(x86)}\VMware\VMware Workstation\vmrun.exe"
)) {
    if (Test-Path $p) { $vmrun = $p; break }
}

if (-not $vmrun) {
    Write-Host "[!] vmrun.exe not found. Attach ISO manually in VMware." -ForegroundColor Red
    Write-Host "    ISO path: $isoPath" -ForegroundColor Yellow
    exit 0
}

if (-not (Test-Path $VmxPath)) {
    Write-Host "[!] VM not found: $VmxPath" -ForegroundColor Red
    Write-Host "    Set -VmxPath parameter to your victim VM's .vmx file." -ForegroundColor Yellow
    exit 0
}

# Ensure VM is powered off before editing .vmx
$runningVms = & $vmrun -T ws list 2>$null
if ($runningVms -and ($runningVms | Select-String -SimpleMatch $VmxPath -Quiet)) {
    Write-Host "[!] VM is running. Stopping it first..." -ForegroundColor Yellow
    & $vmrun -T ws stop $VmxPath hard
    Start-Sleep -Seconds 2
}

# Take snapshot before infection if name provided
if ($SnapshotName -ne "") {
    Write-Host "    Taking snapshot: $SnapshotName..."
    & $vmrun -T ws snapshot $VmxPath $SnapshotName
}

# Read current vmx, add SATA CD-ROM pointing to ISO
$vmxContent = Get-Content $VmxPath -Raw

# Remove only sata0:0 lines (keep sata0:1, sata0:2 etc. if they exist)
$vmxContent = ($vmxContent -split "`n" | Where-Object { $_ -notmatch '^sata0:0\b' -and $_ -notmatch '^sata0\.present' }) -join "`n"

$sataBlock = @"

sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.deviceType = "cdrom-image"
sata0:0.fileName = "$($isoPath -replace '\\','\\')"
sata0:0.startConnected = "TRUE"
"@

$vmxContent = $vmxContent.TrimEnd() + "`n" + $sataBlock + "`n"
Set-Content -Path $VmxPath -Value $vmxContent -Encoding UTF8

Write-Host "    SATA CD-ROM attached: $isoPath" -ForegroundColor Green

# --- Step 4: Start VM ---
Write-Host ""
Write-Host "[*] Step 4 — Starting VM..." -ForegroundColor Yellow
& $vmrun -T ws start $VmxPath gui
Write-Host "    VM started." -ForegroundColor Green

Write-Host ""
Write-Host "=== Deploy complete ===" -ForegroundColor Cyan
Write-Host "Inside the VM:" -ForegroundColor Yellow
Write-Host "  1. Open D:\ (CD-ROM drive)" -ForegroundColor White
Write-Host "  2. Copy all files to Desktop" -ForegroundColor White
Write-Host "  3. Run as Admin: RevetonDropper.exe sample.dll" -ForegroundColor White
Write-Host ""
Write-Host "After infection, shut down VM and run:" -ForegroundColor Yellow
Write-Host "  .\tools\build_and_deploy.ps1 ... (this script detaches CD-ROM on next run)" -ForegroundColor White
