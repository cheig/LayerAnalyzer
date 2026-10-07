<#
RTP4-QA-02 体积与对齐 —— 16 KB 页面对齐检查脚本

对 APK 内**实际入包**的每个 lib/<abi>/*.so 解包后运行 `llvm-readelf -l`，
打印每个 LOAD 段的类型行与紧随其后的 FileSiz/MemSiz/Flags/Align 行。

用法：
  .\native_build\verification\rtp\qa02_check_alignment.ps1 `
      -Apk app\build\outputs\apk\debug\app-debug.apk `
      -Abi arm64-v8a `
      -Out build\verification\rtp\qa02\alignment-debug-arm64.txt

判定：Android 15+ 要求 LOAD 段的 Align 为 0x4000（16 KB）。本脚本只采集
原始输出，不做“通过/不通过”的裁剪，判定写在报告里，便于逐行核对。

为什么从 APK 解包而不是读 app/build/intermediates 下的中间产物：中间产物是
链接器的直接输出，APK 里的那份才是打包/（release 时）strip 之后真正分发到
设备上的文件。两者都要满足，报告里两份都记录。

不修改任何构建产物。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Apk,
    [Parameter(Mandatory = $true)][string]$Abi,
    [string]$Out,
    [string]$ReadElf = '',
    [string]$WorkDir
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Apk)) { throw "APK not found: $Apk" }
if (-not $ReadElf) {
    $readElfCommand = Get-Command llvm-readelf -ErrorAction SilentlyContinue
    if ($readElfCommand) { $ReadElf = $readElfCommand.Source }
    elseif ($env:ANDROID_NDK_HOME) {
        $ReadElf = Join-Path $env:ANDROID_NDK_HOME 'toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe'
    }
}
if (-not $ReadElf -or -not (Test-Path -LiteralPath $ReadElf)) {
    throw 'Pass -ReadElf, add llvm-readelf to PATH, or set ANDROID_NDK_HOME.'
}

$apkItem = (Resolve-Path -LiteralPath $Apk).Path
if (-not $WorkDir) {
    $WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("qa02-align-" + [guid]::NewGuid().ToString('N'))
}
if (-not (Test-Path -LiteralPath $WorkDir)) { New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null }

$lines = New-Object System.Collections.Generic.List[string]
function Emit([string]$t) { $lines.Add($t); Write-Host $t }

Emit "apk=$apkItem"
Emit "abi=$Abi"
Emit "llvm-readelf=$ReadElf"
Emit ("llvm-readelf_version=" + ((& $ReadElf --version | Select-Object -First 1) -replace '\s+$',''))
Emit "extract_dir=$WorkDir"
Emit ""

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($apkItem)
try {
    $entries = $zip.Entries | Where-Object { $_.FullName -like "lib/$Abi/*.so" } | Sort-Object FullName
    foreach ($e in $entries) {
        $dest = Join-Path $WorkDir (Split-Path -Leaf $e.FullName)
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dest, $true)
    }
}
finally { $zip.Dispose() }

$sos = Get-ChildItem -LiteralPath $WorkDir -Filter '*.so' | Sort-Object Name
Emit "so_count=$($sos.Count)"
Emit ""

foreach ($so in $sos) {
    Emit ">>> $($so.Name)  bytes=$($so.Length)"
    Emit "cmd: llvm-readelf -l `"$($so.FullName)`""
    # 变量名不能叫 $out：PowerShell 变量名大小写不敏感，会覆盖本脚本的 $Out 参数。
    $elfText = @(& $ReadElf -l $so.FullName)
    $loadCount = 0
    $aligns = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $elfText.Count; $i++) {
        if ($elfText[$i] -notmatch '^\s*LOAD\b') { continue }
        $loadCount++
        Emit $elfText[$i]
        # llvm-readelf 把 FileSiz/MemSiz/Flags/Align 放在同一行，Align 是行尾字段。
        # GNU binutils 的 readelf 会把它们折到下一行，所以两种都认。
        $last = ($elfText[$i].Trim() -split '\s+')[-1]
        if ($last -notmatch '^0x[0-9a-fA-F]+$') {
            for ($k = $i + 1; $k -lt $elfText.Count; $k++) {
                if ($elfText[$k].Trim() -ne '') {
                    Emit $elfText[$k]
                    $last = ($elfText[$k].Trim() -split '\s+')[-1]
                    break
                }
            }
        }
        $aligns.Add($last)
    }
    Emit "load_segments=$loadCount"
    Emit "load_align_values=$(($aligns | Sort-Object -Unique) -join ',')"
    Emit ""
}

if ($Out) {
    $outDir = Split-Path -Parent $Out
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    }
    Set-Content -LiteralPath $Out -Value $lines -Encoding UTF8
    Write-Host "written: $Out"
}