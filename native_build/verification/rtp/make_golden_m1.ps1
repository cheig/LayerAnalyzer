<#
.SYNOPSIS
    生成 RTP1-ARCH-02 的 tshark golden（app/src/androidTest/assets/rtp/golden/*.streams.json）。

.DESCRIPTION
    对 app/src/androidTest/assets/rtp/ 下的每个夹具运行 tshark 的 RTP 流统计，并把结果转成
    JSON。golden 必须由脚本产出，禁止手写或手改数值。

    工具链要求：tshark / Wireshark **4.0.10**（见 CONTRIBUTING.md）。脚本第一步校验版本，
    不匹配直接报错退出。4.0.10 与 4.2 的 rtppacket_analyse 在抖动/skew 与乱序处理上不同，
    混用会让 golden 与本项目原生实现对不上。

    可重复运行：输出只有 golden JSON；tshark 的原始输出放 $env:TEMP。

.PARAMETER TsharkPath
    tshark.exe 路径。默认取环境变量 TSHARK_PATH，没有则用 C:\Program Files\Wireshark\tshark.exe。

.EXAMPLE
    .\make_golden_m1.ps1
    $env:TSHARK_PATH = 'C:\tools\ws4010\Wireshark\tshark.exe'; .\make_golden_m1.ps1

.NOTES
    夹具来源与许可证见 CONTRIBUTING.md；
    夹具的派生方法见 make_fixture_g711u_loss_reorder.ps1；
    逐样本期望值与对比口径见 CONTRIBUTING.md。
#>
[CmdletBinding()]
param(
    [string] $TsharkPath,

    # 夹具目录（含 golden/ 子目录），默认 androidTest 资产目录
    [string] $FixtureDir = (Join-Path $PSScriptRoot '..\..\..\app\src\androidTest\assets\rtp')
)

$ErrorActionPreference = 'Stop'
$invariant = [System.Globalization.CultureInfo]::InvariantCulture

# ---- 1. 校验 tshark 版本（C8）-----------------------------------------------
if (-not $TsharkPath) {
    $TsharkPath = $env:TSHARK_PATH
    if (-not $TsharkPath) { $TsharkPath = 'C:\Program Files\Wireshark\tshark.exe' }
}
if (-not (Test-Path $TsharkPath)) {
    throw "找不到 tshark：$TsharkPath（用 -TsharkPath 或环境变量 TSHARK_PATH 指定）"
}
$version = (& $TsharkPath --version | Select-Object -First 1)
if ($version -notmatch '4\.0\.10') {
    throw "需要 Wireshark 4.0.10，当前：$version"
}
Write-Host "使用：$TsharkPath"
Write-Host "版本：$version"

# ---- 2. 夹具清单 -----------------------------------------------------------
# Heuristic = 该夹具需要 --enable-heuristic rtp_udp（没有信令的纯 RTP）。
$fixtures = @(
    [pscustomobject]@{ Name = 'sip_g711a_bidirectional.pcap'; Heuristic = $false },
    [pscustomobject]@{ Name = 'g711u_loss_reorder.pcap';     Heuristic = $false },
    [pscustomobject]@{ Name = 'rtp_no_signal.pcap';          Heuristic = $true  },
    [pscustomobject]@{ Name = 'srtp.pcap';                   Heuristic = $false }
)

$fixtureDirFull = [System.IO.Path]::GetFullPath($FixtureDir)
$goldenDir = Join-Path $fixtureDirFull 'golden'
if (-not (Test-Path $goldenDir)) { New-Item -ItemType Directory -Force -Path $goldenDir | Out-Null }

# ---- 3. 解析 tshark 的 RTP Streams 表格 -------------------------------------
# 输出格式见 reference/wireshark-4.0.10/ui/cli/tap-rtp.c:77
#   %13.6f %13.6f %15s %5u %15s %5u 0x%08X %16s %5u %5d (%.1f%%) %15.3f x6 %s
# Payload 列可能为空、也可能含逗号（如 "g711A, telephone-event"），所以从右侧固定列取字段。
function ConvertTo-RtpStreams {
    param([string[]] $Lines)

    # Payload 列长度可变（可能为空、可能含逗号），因此用"左固定 + 右固定 + 中间惰性"的锚定正则，
    # 而不是按 token 数量对齐。
    $rowPattern = '^\s*(?<start>\S+)\s+(?<end>\S+)\s+(?<src>\S+)\s+(?<srcPort>\d+)\s+(?<dst>\S+)\s+(?<dstPort>\d+)\s+' +
                  '(?<ssrc>0x[0-9A-Fa-f]{8})\s+(?<payload>.*?)\s+(?<packets>\d+)\s+(?<lost>-?\d+)\s+' +
                  '\((?<lostPct>-?[\d.]+)%\)\s+(?<minDelta>-?[\d.]+)\s+(?<meanDelta>-?[\d.]+)\s+(?<maxDelta>-?[\d.]+)\s+' +
                  '(?<minJitter>-?[\d.]+)\s+(?<meanJitter>-?[\d.]+)\s+(?<maxJitter>-?[\d.]+)\s*(?<problems>X)?$'

    $streams = New-Object System.Collections.ArrayList
    $inTable = $false
    $sawHeader = $false
    foreach ($line in $Lines) {
        if (-not $inTable) {
            if ($line -match '={3,}\s*RTP Streams') { $inTable = $true }
            continue
        }
        if ($line -match '^={4,}') { break }                     # 表格结束
        $trimmed = $line.TrimEnd()
        if ($trimmed -eq '') { continue }
        if (-not $sawHeader) { $sawHeader = $true; continue }     # 表头

        $match = [regex]::Match($trimmed, $rowPattern)
        if (-not $match.Success) {
            throw "无法解析 tshark 输出行：$trimmed"
        }
        $stream = [ordered]@{
            src          = $match.Groups['src'].Value
            srcPort      = [int]$match.Groups['srcPort'].Value
            dst          = $match.Groups['dst'].Value
            dstPort      = [int]$match.Groups['dstPort'].Value
            ssrc         = [Convert]::ToUInt32($match.Groups['ssrc'].Value.Substring(2), 16).ToString($invariant)
            payload      = $match.Groups['payload'].Value.Trim()
            packets      = [int]$match.Groups['packets'].Value
            lost         = [int]$match.Groups['lost'].Value
            lostPct      = [double]::Parse($match.Groups['lostPct'].Value, $invariant)
            minDeltaMs   = [double]::Parse($match.Groups['minDelta'].Value, $invariant)
            meanDeltaMs  = [double]::Parse($match.Groups['meanDelta'].Value, $invariant)
            maxDeltaMs   = [double]::Parse($match.Groups['maxDelta'].Value, $invariant)
            minJitterMs  = [double]::Parse($match.Groups['minJitter'].Value, $invariant)
            meanJitterMs = [double]::Parse($match.Groups['meanJitter'].Value, $invariant)
            maxJitterMs  = [double]::Parse($match.Groups['maxJitter'].Value, $invariant)
            problems     = $match.Groups['problems'].Success
        }
        [void]$streams.Add($stream)
    }
    if (-not $inTable) { throw '在 tshark 输出里找不到 "RTP Streams" 表格' }
    return $streams
}

# ---- 4. JSON 序列化（固定字段顺序/缩进/换行，保证可重复）--------------------
function ConvertTo-GoldenJson {
    param([string] $Pcap, [bool] $Heuristic, [System.Collections.IEnumerable] $Streams)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("{`n")
    [void]$sb.Append("  `"source`": `"tshark 4.0.10`",`n")
    [void]$sb.Append(("  `"pcap`": `"{0}`",`n" -f $Pcap))
    [void]$sb.Append(("  `"heuristic`": {0},`n" -f $Heuristic.ToString().ToLowerInvariant()))
    [void]$sb.Append("  `"streams`": [")
    $list = @($Streams)
    if ($list.Count -eq 0) {
        [void]$sb.Append("]`n}")
    }
    else {
        [void]$sb.Append("`n")
        for ($i = 0; $i -lt $list.Count; $i++) {
            $s = $list[$i]
            [void]$sb.Append("    {`n")
            [void]$sb.Append(("      `"src`": `"{0}`",`n" -f $s.src))
            [void]$sb.Append(("      `"srcPort`": {0},`n" -f $s.srcPort))
            [void]$sb.Append(("      `"dst`": `"{0}`",`n" -f $s.dst))
            [void]$sb.Append(("      `"dstPort`": {0},`n" -f $s.dstPort))
            [void]$sb.Append(("      `"ssrc`": `"{0}`",`n" -f $s.ssrc))
            [void]$sb.Append(("      `"payload`": `"{0}`",`n" -f $s.payload))
            [void]$sb.Append(("      `"packets`": {0},`n" -f $s.packets))
            [void]$sb.Append(("      `"lost`": {0},`n" -f $s.lost))
            [void]$sb.Append(("      `"lostPct`": {0},`n" -f $s.lostPct.ToString('0.0', $invariant)))
            [void]$sb.Append(("      `"minDeltaMs`": {0},`n" -f $s.minDeltaMs.ToString('0.000', $invariant)))
            [void]$sb.Append(("      `"meanDeltaMs`": {0},`n" -f $s.meanDeltaMs.ToString('0.000', $invariant)))
            [void]$sb.Append(("      `"maxDeltaMs`": {0},`n" -f $s.maxDeltaMs.ToString('0.000', $invariant)))
            [void]$sb.Append(("      `"minJitterMs`": {0},`n" -f $s.minJitterMs.ToString('0.000', $invariant)))
            [void]$sb.Append(("      `"meanJitterMs`": {0},`n" -f $s.meanJitterMs.ToString('0.000', $invariant)))
            [void]$sb.Append(("      `"maxJitterMs`": {0},`n" -f $s.maxJitterMs.ToString('0.000', $invariant)))
            [void]$sb.Append(("      `"problems`": {0}`n" -f $s.problems.ToString().ToLowerInvariant()))
            if ($i -lt $list.Count - 1) { [void]$sb.Append("    },`n") } else { [void]$sb.Append("    }`n") }
        }
        [void]$sb.Append("  ]`n}")
    }
    return $sb.ToString() + "`n"
}

function Invoke-TsharkRtpStreams {
    param([string] $PcapPath, [bool] $Heuristic)

    $tempOut = Join-Path $env:TEMP ("rtp_streams_{0}.txt" -f ([System.IO.Path]::GetFileNameWithoutExtension($PcapPath)))
    $tsharkArgs = @('-r', $PcapPath, '-q', '-z', 'rtp,streams')
    if ($Heuristic) { $tsharkArgs = @('-r', $PcapPath, '--enable-heuristic', 'rtp_udp', '-q', '-z', 'rtp,streams') }
    & $TsharkPath @tsharkArgs 2>&1 | Out-File -FilePath $tempOut -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw ("tshark 失败（exit {0}）：{1}" -f $LASTEXITCODE, $PcapPath) }
    return (Get-Content -LiteralPath $tempOut)
}

# ---- 5. 逐样本生成 ---------------------------------------------------------
# 换行符用平台原生（Windows=CRLF），与本仓库 core.autocrlf=true 的检出结果一致，
# 这样"重跑脚本"不会在 git status 里留下换行符差异。
$newline = [Environment]::NewLine
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
foreach ($fixture in $fixtures) {
    $pcapPath = Join-Path $fixtureDirFull $fixture.Name
    if (-not (Test-Path $pcapPath)) { throw "夹具不存在：$pcapPath" }

    $lines = Invoke-TsharkRtpStreams -PcapPath $pcapPath -Heuristic $fixture.Heuristic
    $streams = ConvertTo-RtpStreams -Lines $lines

    $goldenPath = Join-Path $goldenDir ($fixture.Name -replace '\.pcap$', '.streams.json')
    $json = ConvertTo-GoldenJson -Pcap $fixture.Name -Heuristic $fixture.Heuristic -Streams $streams
    if ($newline -ne "`n") { $json = $json.Replace("`n", $newline) }
    [System.IO.File]::WriteAllText($goldenPath, $json, $utf8NoBom)

    Write-Host ("{0}: streams={1} heuristic={2} -> {3}" -f $fixture.Name, @($streams).Count, $fixture.Heuristic, [System.IO.Path]::GetFileName($goldenPath))

    # rtp_no_signal 的行为基线：不开启发式时必须是 0 条流（见 CONTRIBUTING.md，仪器测试依赖这条差异）
    if ($fixture.Heuristic) {
        $plain = ConvertTo-RtpStreams -Lines (Invoke-TsharkRtpStreams -PcapPath $pcapPath -Heuristic $false)
        if (@($plain).Count -ne 0) {
            throw ("{0} 在关闭启发式时仍有 {1} 条流，与 CONTRIBUTING.md 记录的行为不符" -f $fixture.Name, @($plain).Count)
        }
        Write-Host ("{0}: 关闭启发式 -> 0 条流（符合预期）" -f $fixture.Name)
    }
}

Write-Host 'golden 生成完成。'
