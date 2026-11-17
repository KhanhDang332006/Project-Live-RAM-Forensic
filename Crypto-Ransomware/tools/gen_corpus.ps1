# gen_corpus.ps1 - tao bo file moi quy mo lon + manifest ground-truth.
# Chay TRONG VICTIM luc con SACH (truoc khi nhiem). Tuong thich PowerShell 2.0 (Win7).
# Khong can Python: tu bam SHA-256 + magic + header16 ghi thang ra manifest (dung cot nhu make_manifest.py).
#
#   powershell -ExecutionPolicy Bypass -File gen_corpus.ps1
#   powershell -ExecutionPolicy Bypass -File gen_corpus.ps1 -SmallCount 2000 -MedCount 300 -BigCount 20   # nhe hon
#
# Seed co dinh => lan nao chay cung ra bo Y HET => manifest tai dung duoc sau moi lan revert.

param(
  [string]$Root       = "C:\plain",
  [string]$Manifest   = "C:\manifest_bigrun.csv",
  [int]$Seed          = 334,
  [int]$SmallCount    = 4000,   # 2 KB - 100 KB
  [int]$MedCount      = 600,    # 100 KB - 1.5 MB
  [int]$BigCount      = 40      # 2 MB - 20 MB  (vuot nguong ma hoa mot phan)
)
$ErrorActionPreference = "Stop"

$rand = New-Object System.Random($Seed)
$sha  = [System.Security.Cryptography.SHA256]::Create()

$extEnc  = @(".doc",".docx",".xls",".xlsx",".pdf",".zip",".pptx",".sql",".bak")   # ky vong BI ma hoa
$extSkip = @(".txt",".csv",".jpg",".png",".log",".dll",".exe")                    # ky vong BO QUA (xac nhan lai thuc te)
$dirs = @("Documents\HopDong","Documents\BaoCao","Documents\KeToan","Pictures\DuAn",
          "Projects\src","Projects\data","Downloads","Desktop\Temp",
          "FakeWindows\System32","FakeWindows\WinSxS")                            # thu muc "giong he thong" de test skip-list
foreach($d in $dirs){ New-Item -ItemType Directory -Force (Join-Path $Root $d) | Out-Null }

# manifest: UTF-8 co BOM (= utf-8-sig, khop decrypt.py / Excel)
$enc = New-Object System.Text.UTF8Encoding($true)
$mf  = New-Object System.IO.StreamWriter($Manifest, $false, $enc)
$mf.WriteLine("filename,ext,size,sha256,magic_hex,header16_hex")

function HexN($bytes, $count){
  $sb = New-Object System.Text.StringBuilder
  $m = $count; if($bytes.Length -lt $m){ $m = $bytes.Length }
  for($j=0; $j -lt $m; $j++){ [void]$sb.Append($bytes[$j].ToString("x2")) }
  return $sb.ToString()
}

function Write-Corpus-File($relFwd, $ext, $size, $tag){
  $full = Join-Path $Root ($relFwd.Replace("/","\"))
  $dir  = Split-Path $full
  if(-not (Test-Path $dir)){ New-Item -ItemType Directory -Force $dir | Out-Null }
  $buf = New-Object byte[] $size
  $rand.NextBytes($buf)
  # 64 byte dau la "header" nhan dang duoc (known-plaintext cho canary): chuoi co dinh
  $hdr = [Text.Encoding]::ASCII.GetBytes($tag.PadRight(64, [char]46))
  [Array]::Copy($hdr, $buf, [Math]::Min($hdr.Length, $size))
  [IO.File]::WriteAllBytes($full, $buf)
  $hash = HexN $sha.ComputeHash($buf) 32
  $mf.WriteLine(("{0},{1},{2},{3},{4},{5}" -f $relFwd, $ext, $size, $hash, (HexN $buf 8), (HexN $buf 16)))
}

$i = 0
function Place([int]$n, [int]$min, [int]$max){
  for($k=0; $k -lt $n; $k++){
    $script:i++
    $d = $dirs[$rand.Next($dirs.Count)]
    if($rand.NextDouble() -lt 0.75){ $ext = $extEnc[$rand.Next($extEnc.Count)] }
    else { $ext = $extSkip[$rand.Next($extSkip.Count)] }
    $size = $rand.Next($min, $max)
    $relFwd = ($d + "\" + ("f{0:D6}{1}" -f $script:i, $ext)).Replace("\","/")
    Write-Corpus-File $relFwd $ext.TrimStart(".") $size ("LABFILE;seed=" + $Seed + ";i=" + $script:i + ";")
  }
}

Place $SmallCount 2048   102400
Place $MedCount   102400 1536000
Place $BigCount   2097152 20971520

# 5 file canary biet truoc ban ro (cho known-plaintext key-scan neu can)
foreach($c in @("Documents/book.zip","Documents/baocao.pdf","Documents/note.doc","Documents/so_ketoan.xls","Documents/ketqua.docx")){
  $script:i++
  $ext = [IO.Path]::GetExtension($c).TrimStart(".")
  Write-Corpus-File $c $ext 40000 ("LABFILE;canary;" + $c + ";")
}

$mf.Close()
$sha.Clear()

$all = Get-ChildItem $Root -Recurse | Where-Object { -not $_.PSIsContainer }
$sum = ($all | Measure-Object Length -Sum).Sum
Write-Host ("Da tao {0} file ({1:N2} GB) duoi {2}" -f $all.Count, ($sum/1GB), $Root)
Write-Host ("Manifest: {0}" -f $Manifest)
