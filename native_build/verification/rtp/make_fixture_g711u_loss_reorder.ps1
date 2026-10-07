<#
.SYNOPSIS
    派生 RTP1-ARCH-02 夹具 g711u_loss_reorder.pcap（G.711U + 丢包 + 乱序）。

.DESCRIPTION
    源样本：Wireshark SampleCaptures 的 sip-rtp-g711.pcap（SIPp <-> FreeSWITCH 实验室场景，
    PCMU 会话，10.0.2.0/24 私网地址）。源样本本身没有任何丢包和乱序，所以本脚本在**保留
    原始帧顺序**的前提下，对其中 PCMU 会话做两处最小改动：

      1. 丢掉若干个媒体包（制造 lost / WRONG_SEQ）；
      2. 交换两对相邻媒体帧的先后（制造 late/duplicated 分支，即乱序）。

    只保留 PCMU 会话的 SIP 帧（Call-ID 1-1966@10.0.2.20）与协商出的媒体方向
    （10.0.2.15:27942 -> 10.0.2.20:6000），其余帧（PCMA 会话、地址端口自环的杂散帧）全部丢弃，
    使夹具只包含"一条被 SIP/SDP 协商出来的 G.711U 流"。

    脚本可重复运行：下载的源样本放 $env:TEMP，输出只有 g711u_loss_reorder.pcap 一个文件。

.NOTES
    夹具来源与许可证记录见 CONTRIBUTING.md；
    golden 生成见同目录 make_golden_m1.ps1，说明见 CONTRIBUTING.md。
#>
[CmdletBinding()]
param(
    # 已下载的源样本路径；省略时从 $DownloadUrl 下载到 $env:TEMP
    [string] $SourcePcap,

    [string] $DownloadUrl = 'https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/sip-rtp-g711.pcap',

    # 输出路径，默认写入 androidTest 资产目录
    [string] $OutputPath = (Join-Path $PSScriptRoot '..\..\..\app\src\androidTest\assets\rtp\g711u_loss_reorder.pcap'),

    # 要丢弃的媒体包序号（1 起，按保留后的媒体顺序计），默认丢 4 个
    [int[]] $DropMediaIndex = @(100, 200, 300, 400),

    # 要交换的相邻媒体包对（1 起，交换 i 与 i+1）
    [int[]] $SwapMediaIndex = @(150, 320),

    # 期望的源样本 / 输出样本 SHA-256（用于发现上游样本变化或本地误改）
    [string] $ExpectSourceSha256 = '6BE243F86C57646B8B506D7CC0F2B4E37740C5A7DB3F22944078C402DB37D8F7',

    [string] $ExpectOutputSha256 = '28F43B78D0F95A8637A69530D11A0E88A24B23026905993A1AEE1C9414D9B4D3'
)

$ErrorActionPreference = 'Stop'

# ---- 源样本 ----------------------------------------------------------------
if (-not $SourcePcap) {
    $SourcePcap = Join-Path $env:TEMP 'sip-rtp-g711.pcap'
    Write-Host "下载源样本：$DownloadUrl"
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $SourcePcap -UseBasicParsing
}
if (-not (Test-Path $SourcePcap)) { throw "源样本不存在：$SourcePcap" }

$sourceBytes = [System.IO.File]::ReadAllBytes($SourcePcap)
if ($ExpectSourceSha256 -and $ExpectSourceSha256 -ne 'FILL_IN') {
    $sha = (Get-FileHash -Algorithm SHA256 -Path $SourcePcap).Hash
    if ($sha -ne $ExpectSourceSha256) { throw "源样本 SHA-256 不匹配：$sha" }
}

# ---- 解析经典 pcap ---------------------------------------------------------
# 全局头 24 字节：magic(4) major(2) minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
if ($sourceBytes.Length -lt 24) { throw "文件太小，不是 pcap：$SourcePcap" }
# 按字节比较，避免 PowerShell 十六进制字面量的 Int32 符号问题
$magicOk = ($sourceBytes[0] -eq 0xd4) -and ($sourceBytes[1] -eq 0xc3) -and ($sourceBytes[2] -eq 0xb2) -and ($sourceBytes[3] -eq 0xa1)
if (-not $magicOk) {
    $hex = ($sourceBytes[0..3] | ForEach-Object { '{0:x2}' -f $_ }) -join ''
    throw "只支持小端经典 pcap（magic d4c3b2a1），实际 $hex：$SourcePcap"
}

$records = New-Object System.Collections.ArrayList
$offset = 24
while ($offset + 16 -le $sourceBytes.Length) {
    $inclLen = [System.BitConverter]::ToUInt32($sourceBytes, $offset + 8)
    if ($offset + 16 + $inclLen -gt $sourceBytes.Length) { break }
    $frame = New-Object byte[] $inclLen
    [System.Array]::Copy($sourceBytes, $offset + 16, $frame, 0, $inclLen)
    $record = [pscustomobject]@{
        Header = $sourceBytes[$offset..($offset + 15)]
        Frame  = $frame
    }
    [void]$records.Add($record)
    $offset += 16 + $inclLen
}
Write-Host ("源样本帧数：{0}" -f $records.Count)

# ---- 五元组解析（以太网 + IPv4 + UDP）--------------------------------------
# 注意：pcap 记录头是小端（magic d4c3b2a1），但以太网类型、端口等网络字段是大端。
function Read-NetU16 {
    param([byte[]] $Bytes, [int] $Offset)
    return ([int]$Bytes[$Offset] * 256 + [int]$Bytes[$Offset + 1])
}

function Get-UdpTuple {
    param([byte[]] $Frame)
    if ($Frame.Length -lt 42) { return $null }
    # 以太网：目的 MAC(6) 源 MAC(6) 类型(2)；跳过 VLAN（0x8100）
    $etherType = Read-NetU16 -Bytes $Frame -Offset 12
    $ipOffset = 14
    while ($etherType -eq 0x8100 -and $Frame.Length -gt ($ipOffset + 4)) {
        $etherType = Read-NetU16 -Bytes $Frame -Offset ($ipOffset + 2)
        $ipOffset += 4
    }
    if ($etherType -ne 0x0800) { return $null }              # 只处理 IPv4
    if ($Frame.Length -lt ($ipOffset + 20)) { return $null }
    $ihl = ($Frame[$ipOffset] -band 0x0f) * 4
    if ($ihl -lt 20) { return $null }
    $protocol = $Frame[$ipOffset + 9]
    if ($protocol -ne 17) { return $null }                   # 只处理 UDP
    $udpOffset = $ipOffset + $ihl
    if ($Frame.Length -lt ($udpOffset + 8)) { return $null }
    $udpLen = Read-NetU16 -Bytes $Frame -Offset ($udpOffset + 4)
    if ($udpLen -lt 8) { $udpLen = 8 }
    if ($Frame.Length -lt ($udpOffset + $udpLen)) { $udpLen = $Frame.Length - $udpOffset }
    $payloadLen = $udpLen - 8
    return [pscustomobject]@{
        SrcPort    = Read-NetU16 -Bytes $Frame -Offset $udpOffset
        DstPort    = Read-NetU16 -Bytes $Frame -Offset ($udpOffset + 2)
        PayloadOff = $udpOffset + 8
        PayloadLen = $payloadLen
    }
}

function Test-ContainsAscii {
    param([byte[]] $Frame, [int] $Offset, [int] $Length, [string] $Needle)
    if ($Length -le 0) { return $false }
    $text = [System.Text.Encoding]::ASCII.GetString($Frame, $Offset, $Length)
    return $text.Contains($Needle)
}

# ---- 选出 PCMU 会话的帧 ----------------------------------------------------
$mediaPorts = @(27942, 6000)          # 协商出的媒体方向：10.0.2.15:27942 -> 10.0.2.20:6000
$callId = '1-1966@10.0.2.20'          # PCMU 会话（PCMA 会话是 1-1968@10.0.2.20）

$kept = New-Object System.Collections.ArrayList       # 保留的帧（保持原顺序）
$mediaPositions = New-Object System.Collections.ArrayList   # 各媒体帧在 $kept 中的下标
foreach ($record in $records) {
    $tuple = Get-UdpTuple -Frame $record.Frame
    if ($null -eq $tuple) { continue }
    $isMedia = ($tuple.SrcPort -eq $mediaPorts[0]) -and ($tuple.DstPort -eq $mediaPorts[1])
    $isSip = (Test-ContainsAscii -Frame $record.Frame -Offset $tuple.PayloadOff -Length $tuple.PayloadLen -Needle $callId)
    if (-not ($isMedia -or $isSip)) { continue }
    if ($isMedia) { [void]$mediaPositions.Add($kept.Count) }
    [void]$kept.Add($record)
}
Write-Host ("保留帧数：{0}（其中媒体 {1}）" -f $kept.Count, $mediaPositions.Count)
if ($mediaPositions.Count -eq 0) { throw '没有找到媒体帧，源样本可能与预期不符' }

# ---- 改动 1：丢包 ----------------------------------------------------------
$dropPositions = @{}
foreach ($oneBased in $DropMediaIndex) {
    $index = $oneBased - 1
    if ($index -lt 0 -or $index -ge $mediaPositions.Count) { throw "DropMediaIndex 越界：$oneBased" }
    $dropPositions[[int]$mediaPositions[$index]] = $true
}

# ---- 改动 2：交换相邻媒体帧 ------------------------------------------------
$swapPairs = New-Object System.Collections.ArrayList
foreach ($oneBased in $SwapMediaIndex) {
    $index = $oneBased - 1
    if ($index -lt 0 -or ($index + 1) -ge $mediaPositions.Count) { throw "SwapMediaIndex 越界：$oneBased" }
    [void]$swapPairs.Add(@([int]$mediaPositions[$index], [int]$mediaPositions[$index + 1]))
}

$order = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $kept.Count; $i++) { [void]$order.Add($i) }
foreach ($pair in $swapPairs) {
    $a = $order.IndexOf($pair[0])
    $b = $order.IndexOf($pair[1])
    if ($a -ge 0 -and $b -ge 0) {
        $tmp = $order[$a]; $order[$a] = $order[$b]; $order[$b] = $tmp
    }
}

# ---- 写出 ------------------------------------------------------------------
$outputStream = New-Object System.IO.MemoryStream
$outputStream.Write($sourceBytes, 0, 24)
$written = 0
foreach ($index in $order) {
    if ($dropPositions.ContainsKey([int]$index)) { continue }
    $record = $kept[$index]
    $outputStream.Write($record.Header, 0, 16)
    $outputStream.Write($record.Frame, 0, $record.Frame.Length)
    $written++
}

$outputFull = [System.IO.Path]::GetFullPath($OutputPath)
$outputDir = [System.IO.Path]::GetDirectoryName($outputFull)
if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Force -Path $outputDir | Out-Null }
[System.IO.File]::WriteAllBytes($outputFull, $outputStream.ToArray())

Write-Host ("写出 {0}（{1} 帧，丢弃 {2} 帧，交换 {3} 对）" -f $outputFull, $written, $dropPositions.Count, $swapPairs.Count)
$outputSha = (Get-FileHash -Algorithm SHA256 -Path $outputFull).Hash
Write-Host ("SHA-256: {0}" -f $outputSha)
if ($ExpectOutputSha256 -and $ExpectOutputSha256 -ne 'FILL_IN' -and $outputSha -ne $ExpectOutputSha256) {
    throw "输出 SHA-256 不匹配（期望 $ExpectOutputSha256）"
}
