<#
capture.ps1 - chup RAM VM VMware dinh ky, ghi capture_log.csv

Chay tren MAY THAT (Windows), khong chay trong VM. Moi lan chup:
  1. vmrun snapshot  -> VMware ghi RAM hien tai ra <vm>-SnapshotN.vmem + .vmsn,
     VM van chay lien tuc nen khong lam lech timeline khoa.
  2. Tim 2 file moi vua sinh ra, noi (hardlink) sang OutDir roi dat ten
     mem_<giay>s.vmem / .vmsn. Hardlink = tuc thi, khong ton them dung luong;
     neu khac o dia thi tu dong copy.
  3. Ghi 1 dong vao capture_log.csv: file,dump_time,elapsed_s,duration_s
Cuoi cung xoa cac snapshot da tao (tru snapshot co san nhu clean-baseline).
Du lieu RAM da noi sang OutDir nen xoa snapshot khong mat dump.

Dung luong can: SoLanChup x RAM cua VM (RAM 4 GB, 20 lan = ~80 GB).

Vi du:
  .\capture.ps1 -Vmx "D:\VM\Win10-VICTIM\Win10-VICTIM.vmx" -IntervalSec 30 -Count 10 -OutDir D:\evidence\run01
  .\capture.ps1 -Vmx "..." -Count 3 -IntervalSec 20 -NoWait      # bat dau chup ngay, khong cho Enter
  .\capture.ps1 -Vmx "..." -DryRun                                # chi kiem tra vmrun/VM, khong chup

Quy trinh: chay script -> khi script hoi, bam Enter DUNG LUC bat dau chay mau/keyholder trong VM
(elapsed_s = so giay tinh tu luc bam Enter). Script khong tu chay mau trong VM.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Vmx,
    [int]$IntervalSec = 30,
    [int]$Count = 10,
    [string]$OutDir = ".\captures",
    [string]$Prefix = "mem",
    [string]$Vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
    [switch]$NoWait,
    [switch]$ForceCopy,
    [switch]$KeepSnapshots,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Fail($msg) { Write-Host "[!] $msg" -ForegroundColor Red; exit 1 }
function Info($msg) { Write-Host "[=] $msg" }

if (-not (Test-Path -LiteralPath $Vmrun)) { Fail "Khong thay vmrun.exe: $Vmrun (dung -Vmrun de chi duong dan)" }
if (-not (Test-Path -LiteralPath $Vmx))   { Fail "Khong thay file .vmx: $Vmx" }
if ($IntervalSec -lt 1 -or $Count -lt 1)  { Fail "IntervalSec va Count phai >= 1" }

$Vmx = (Resolve-Path -LiteralPath $Vmx).Path
$vmDir = Split-Path -Parent $Vmx

# VM phai dang chay moi chup duoc RAM
$running = & $Vmrun -T ws list
if (-not ($running | Where-Object { $_ -ieq $Vmx })) {
    Fail "VM chua chay (Power On) hoac duong dan .vmx khong khop voi 'vmrun list'. Dang chay:`n$($running -join "`n")"
}

# canh bao dung luong
$ramFiles = Get-ChildItem -LiteralPath $vmDir -Filter *.vmem -ErrorAction SilentlyContinue | Sort-Object Length -Descending
$ramBytes = if ($ramFiles) { $ramFiles[0].Length } else { 0 }
$outFull = [System.IO.Path]::GetFullPath($OutDir)
$driveName = [System.IO.Path]::GetPathRoot($outFull).TrimEnd('\').TrimEnd(':')
$free = (Get-PSDrive -Name $driveName).Free
$need = [int64]$ramBytes * $Count
Info ("VM: {0}" -f $Vmx)
Info ("RAM moi dump ~ {0:N1} GB, can ~ {1:N1} GB, o {2}: con {3:N1} GB" -f ($ramBytes / 1GB), ($need / 1GB), $driveName, ($free / 1GB))
if ($ramBytes -gt 0 -and $free -lt ($need + 5GB)) { Fail "Khong du dung luong trong. Giam -Count hoac doi -OutDir sang o khac." }

if ($DryRun) {
    Info "DryRun: vmrun, .vmx va dung luong deu on. Se chup $Count lan, moi $IntervalSec giay, ghi vao $outFull"
    exit 0
}

New-Item -ItemType Directory -Force -Path $outFull | Out-Null
$log = Join-Path $outFull "capture_log.csv"
if (-not (Test-Path -LiteralPath $log)) {
    Set-Content -LiteralPath $log -Value "file,dump_time,elapsed_s,duration_s" -Encoding ASCII
}

if (-not $NoWait) {
    Read-Host "Bam Enter DUNG LUC bat dau chay mau/keyholder trong VM (moc elapsed_s = 0)"
}
$t0 = Get-Date
Info ("Bat dau luc {0}. Chup {1} lan, moi {2}s." -f $t0.ToString("yyyy-MM-ddTHH:mm:sszzz"), $Count, $IntervalSec)

$snapNames = @()
try {
    for ($i = 0; $i -lt $Count; $i++) {
        # lich co dinh: lan i chup tai t0 + i*Interval, khong tich luy tre
        $due = $t0.AddSeconds($i * $IntervalSec)
        $wait = ($due - (Get-Date)).TotalSeconds
        if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }

        $before = @(Get-ChildItem -LiteralPath $vmDir -File | Where-Object { $_.Extension -in ".vmem", ".vmsn" } | ForEach-Object { $_.Name })

        $snap = "{0}_{1:0000}" -f $Prefix, ($i * $IntervalSec)
        $start = Get-Date
        & $Vmrun -T ws snapshot $Vmx $snap | Out-Null
        $dur = ((Get-Date) - $start).TotalSeconds
        $snapNames += $snap

        $new = @(Get-ChildItem -LiteralPath $vmDir -File | Where-Object { $_.Extension -in ".vmem", ".vmsn" -and $before -notcontains $_.Name })
        $newMem = $new | Where-Object { $_.Extension -eq ".vmem" } | Select-Object -First 1
        $newSn  = $new | Where-Object { $_.Extension -eq ".vmsn" } | Select-Object -First 1
        if (-not $newMem) {
            Write-Host "[!] Lan $i : khong thay .vmem moi (snapshot khong kem RAM?). Bo qua." -ForegroundColor Yellow
            continue
        }

        $base = "{0}_{1:0000}s" -f $Prefix, ($i * $IntervalSec)
        foreach ($src in @($newMem, $newSn)) {
            if (-not $src) { continue }
            $dst = Join-Path $outFull ($base + $src.Extension)
            if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Force }
            $linked = $false
            if (-not $ForceCopy) {
                try { New-Item -ItemType HardLink -Path $dst -Target $src.FullName | Out-Null; $linked = $true } catch { $linked = $false }
            }
            if (-not $linked) { Copy-Item -LiteralPath $src.FullName -Destination $dst }
        }

        $elapsed = [int][math]::Round(($start - $t0).TotalSeconds)
        $row = "{0}.vmem,{1},{2},{3:N1}" -f $base, $start.ToString("yyyy-MM-ddTHH:mm:sszzz"), $elapsed, $dur
        Add-Content -LiteralPath $log -Value $row -Encoding ASCII
        Info ("Lan {0}/{1}: {2}.vmem  t={3}s  mat {4:N1}s" -f ($i + 1), $Count, $base, $elapsed, $dur)
        if ($dur -gt $IntervalSec) {
            Write-Host ("[!] Chup mat {0:N1}s lau hon chu ky {1}s: tang -IntervalSec." -f $dur, $IntervalSec) -ForegroundColor Yellow
        }
    }
}
finally {
    if (-not $KeepSnapshots) {
        foreach ($n in $snapNames) {
            Info "Xoa snapshot $n"
            try { & $Vmrun -T ws deleteSnapshot $Vmx $n | Out-Null } catch { Write-Host "[!] Khong xoa duoc $n : $_" -ForegroundColor Yellow }
        }
    } elseif ($snapNames.Count) {
        Write-Host "[!] Giu lai $($snapNames.Count) snapshot (-KeepSnapshots), nho xoa tay de khoi ton o dia." -ForegroundColor Yellow
    }
}
Info "Xong. Dump + capture_log.csv nam o: $outFull"
Info "Buoc tiep: copy .vmem/.vmsn sang Kali, hash_evidence.py acquire cho moi dump, chay keyscan tung dump."
