<#
RTP4-QA-02 体积与对齐 —— APK 体积测量脚本

用法：
  .\native_build\verification\rtp\qa02_measure_apk.ps1 `
      -Label head-debug-arm64 `
      -Apk app\build\outputs\apk\debug\app-debug.apk `
      -Out build\verification\rtp\qa02\<label>.txt

输出（同时打印到 stdout 并写入 -Out）：
  - APK 文件总字节数（磁盘上的实际文件，注意 APK 对齐填充会算进去）
  - APK 内每个 lib/<abi>/*.so 条目的未压缩字节数
  - 每个 lib/<abi>/*.so 条目的压缩后字节数
  - lib/<abi> 下 .so 条目数（用于确认 ABI/.so 数量没有变化）

为什么同时记录未压缩与压缩后大小：本项目的 debug APK 用
useLegacyPackaging=false，原生库以 STORED（不压缩）方式入包，所以两者对 .so
是一样的；release 构建同样。记录两者是为了让“体积增量”的口径可核对——
增量取未压缩大小之差（这是解包后设备上真实占用的大小）。

不修改任何构建产物。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Label,
    [Parameter(Mandatory = $true)][string]$Apk,
    [string]$Out
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Apk)) {
    throw "APK not found: $Apk"
}

$apkItem = Get-Item -LiteralPath $Apk
$lines = New-Object System.Collections.Generic.List[string]

function Emit([string]$text) {
    $lines.Add($text)
    Write-Host $text
}

Emit "label=$Label"
Emit "apk=$($apkItem.FullName)"
Emit "apk_bytes=$($apkItem.Length)"
Emit "apk_sha256=$((Get-FileHash -LiteralPath $Apk -Algorithm SHA256).Hash.ToLower())"
Emit "apk_last_write=$($apkItem.LastWriteTime.ToString('yyyy-MM-ddTHH:mm:ss'))"
Emit ""

# ZIP 中央目录解析（System.IO.Compression 只给压缩后大小与未压缩大小，
# 正是需要的两项；不依赖 Expand-Archive，也不修改 APK）。
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($apkItem.FullName)
try {
    $libEntries = $zip.Entries | Where-Object { $_.FullName -like 'lib/*' -and $_.FullName -like '*.so' } |
        Sort-Object FullName

    Emit "so_entry_count=$($libEntries.Count)"
    foreach ($abi in ($libEntries | ForEach-Object { ($_.FullName -split '/')[1] } | Sort-Object -Unique)) {
        $n = ($libEntries | Where-Object { $_.FullName -like "lib/$abi/*" }).Count
        Emit "so_entry_count[$abi]=$n"
    }
    Emit ""

    Emit "entry`tuncompressed_bytes`tcompressed_bytes"
    $totalUncompressed = 0
    foreach ($e in $libEntries) {
        $totalUncompressed += $e.Length
        Emit "$($e.FullName)`t$($e.Length)`t$($e.CompressedLength)"
    }
    Emit ""
    Emit "so_total_uncompressed_bytes=$totalUncompressed"
    Emit "apk_non_so_bytes=$($apkItem.Length - $totalUncompressed)"
}
finally {
    $zip.Dispose()
}

if ($Out) {
    $outDir = Split-Path -Parent $Out
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    }
    Set-Content -LiteralPath $Out -Value $lines -Encoding ASCII
    Write-Host ""
    Write-Host "written: $Out"
}