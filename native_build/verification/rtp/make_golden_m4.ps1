<#
.SYNOPSIS
    生成 RTP4-QA-01 的参考 PCM（app/src/androidTest/assets/rtp/golden/*.pcm）。

.DESCRIPTION
    对每个 M4 夹具，脚本做三件**与本项目实现无关**的事：

      1. 用 **tshark** 把目标流的 RTP 负载逐包导出成十六进制（`-T fields -e rtp.payload`），
         绝不使用 LayerAnalyzer 自己的提取路径；
      2. 用 `rtp_reference_bitstream.py` 把负载还原成参考解码器认识的码流/容器
         （裸流、iLBC storage、AMR storage、Ogg Opus）；
      3. 用 **ffmpeg** 解码成小端 16 位 PCM，裁到前 N 秒后写成 golden。

    golden 只能由本脚本产出，禁止手写或手改数值。脚本可重复运行：下载/中间文件都在
    $env:TEMP，输出只有 golden/*.pcm。

    版本口径：要求涉及 **rtppacket_analyse**（抖动/skew/乱序）
    的 golden 必须用 Wireshark/tshark 4.0.10。本脚本只读 `rtp.payload` 这一个字段的原始
    字节（载荷内容与 Wireshark 版本无关，且不读任何统计字段），参考**音频**完全由 ffmpeg
    产生，因此 4.0.10 的版本门禁在这条路径上没有保护对象；默认仍然按 C8 严格校验版本，
    本机只有 4.0.6 时必须显式传 -AllowOtherTshark，并把版本号记进 CONTRIBUTING.md。

.PARAMETER TsharkPath
    tshark.exe 路径。默认取环境变量 TSHARK_PATH，没有则用 C:\Program Files\Wireshark\tshark.exe。

.PARAMETER FfmpegPath
    ffmpeg 可执行文件路径。必填：参考音频只能来自这个独立的解码器。

.PARAMETER Seconds
    每个 golden 保留的秒数（默认 3）。裁剪长度记在 CONTRIBUTING.md 里。

.PARAMETER AllowOtherTshark
    允许非 4.0.10 的 tshark（见上面的版本口径）。

.EXAMPLE
    .\make_golden_m4.ps1 -FfmpegPath C:\tools\ffmpeg\ffmpeg.exe
    .\make_golden_m4.ps1 -FfmpegPath .\ffmpeg.exe -AllowOtherTshark

.NOTES
    夹具来源与许可证见 CONTRIBUTING.md；
    全部命令、版本号、裁剪长度与 SHA-256 见 CONTRIBUTING.md。
#>
[CmdletBinding()]
param(
    [string] $TsharkPath,

    [Parameter(Mandatory = $true)]
    [string] $FfmpegPath,

    # 夹具目录（含 golden/ 子目录），默认 androidTest 资产目录
    [string] $FixtureDir = (Join-Path $PSScriptRoot '..\..\..\app\src\androidTest\assets\rtp'),

    [int] $Seconds = 3,

    [switch] $AllowOtherTshark
)

$ErrorActionPreference = 'Stop'

# ---- 1. 工具链版本 ---------------------------------------------------------
if (-not $TsharkPath) {
    $TsharkPath = $env:TSHARK_PATH
    if (-not $TsharkPath) { $TsharkPath = 'C:\Program Files\Wireshark\tshark.exe' }
}
if (-not (Test-Path $TsharkPath)) {
    throw "找不到 tshark：$TsharkPath（用 -TsharkPath 或环境变量 TSHARK_PATH 指定）"
}
$tsharkVersion = (& $TsharkPath --version | Select-Object -First 1)
if ($tsharkVersion -notmatch '4\.0\.10') {
    if (-not $AllowOtherTshark) {
        throw "需要 Wireshark 4.0.10（C8），当前：$tsharkVersion。确定这条路径不依赖 " +
              "rtppacket_analyse 时用 -AllowOtherTshark 显式放行。"
    }
    Write-Warning "tshark 不是 4.0.10：$tsharkVersion（-AllowOtherTshark 已放行）"
}

if (-not (Test-Path $FfmpegPath)) { throw "找不到 ffmpeg：$FfmpegPath" }
$ffmpegVersion = (& $FfmpegPath -hide_banner -version | Select-Object -First 1)

Write-Host "tshark : $TsharkPath"
Write-Host "tshark version : $tsharkVersion"
Write-Host "ffmpeg : $FfmpegPath"
Write-Host "ffmpeg version : $ffmpegVersion"
Write-Host ''

$fixtureDirFull = [System.IO.Path]::GetFullPath($FixtureDir)
$goldenDir = Join-Path $fixtureDirFull 'golden'
if (-not (Test-Path $goldenDir)) { New-Item -ItemType Directory -Force -Path $goldenDir | Out-Null }

$workDir = Join-Path $env:TEMP 'layanalyzer-rtp-m4'
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$pythonHelper = Join-Path $PSScriptRoot 'rtp_reference_bitstream.py'
$generated = @()

# ---- 2. 夹具清单 -----------------------------------------------------------
# Fixture / Ssrc / SrcIp / SrcPort 是 tshark 的选择条件；Kind 决定中间码流怎么组装；
# Decode 是交给 ffmpeg 的输入参数；Rate 是解码输出的采样率（必须与断言的一致）。
$cases = @(
    [pscustomobject]@{
        Fixture = 'sip_rtp_g722.pcap'; Sha256 = '838639FE064DF7B4076EFEC319CA80EE124D8D4C9118B1CC929524121C361413'
        Ssrc = 0x043DAABA; SrcIp = '10.0.2.15'; SrcPort = 17472
        Codec = 'g722'; Rate = 16000
        Kind = 'raw'; Bitstream = 'g722.raw'; Decode = @('-f', 'g722'); ExpectedPackets = 425
    },
    [pscustomobject]@{
        Fixture = 'sip_rtp_g726.pcap'; Sha256 = '89282263E575CF1497342A1B38586E6FCCED32CB15E21B798748A49D8DAB545F'
        Ssrc = 0x043DA9D6; SrcIp = '10.0.2.15'; SrcPort = 18180
        Codec = 'G726-32'; Rate = 8000
        # RFC 3551 的 G726-* 是 right-justified 打包，ffmpeg 里对应 g726le（little-endian）。
        Kind = 'raw'; Bitstream = 'g726-32.raw'; Decode = @('-f', 'g726le', '-code_size', '4')
        ExpectedPackets = 425
    },
    [pscustomobject]@{
        Fixture = 'sip_rtp_g729.pcap'; Sha256 = '8573F2F7ADF019E743A8C41D9146DF256C67AFDD66169A64323B61EDAA55476A'
        Ssrc = 0x044559A1; SrcIp = '10.0.2.15'; SrcPort = 28120
        Codec = 'g729'; Rate = 8000
        Kind = 'raw'; Bitstream = 'g729.raw'; Decode = @('-f', 'g729'); ExpectedPackets = 425
    },
    [pscustomobject]@{
        Fixture = 'sip_rtp_opus.pcap'; Sha256 = 'C8920238EDCC96188047812A05E9D2CE84A4094529A3434FEA1EA3D92B713FDE'
        Ssrc = 0x043EEE04; SrcIp = '10.0.2.15'; SrcPort = 24196
        Codec = 'opus'; Rate = 48000
        Kind = 'ogg-opus'; Bitstream = 'opus.ogg'; Decode = @(); ExpectedPackets = 425
    },
    [pscustomobject]@{
        Fixture = 'sip_rtp_ilbc.pcap'; Sha256 = '65E313EE78429C829B9B5C7D86975812F8C1F9C7EA06DC3888C900EFB013F9B8'
        Ssrc = 0x043EEFA7; SrcIp = '10.0.2.15'; SrcPort = 25256
        Codec = 'iLBC'; Rate = 8000
        Kind = 'ilbc'; Bitstream = 'ilbc30.ilbc'; Decode = @('-f', 'ilbc'); ExpectedPackets = 284
    },
    [pscustomobject]@{
        Fixture = 'sip_rtp_amr_nb.pcap'; Sha256 = '4C190FF6B9BB681B794B6EDFB5822DB38EB530C5BF246C30E8B6C5D75807B7A0'
        Ssrc = 0x4C41594C; SrcIp = '192.0.2.20'; SrcPort = 40000
        Codec = 'AMR'; Rate = 8000
        # libopencore_amrnb, not ffmpeg's own `amrnb`: at 12.2 kbit/s the choice of
        # *which* independent AMR decoder produces the reference dominates the
        # metric -- the two ffmpeg AMR-NB decoders agree with each other at only
        # 0.9689 on this very bitstream (see CONTRIBUTING.md). The AOSP
        # platform decoder is of the same OpenCORE/3GPP lineage, so the opencore
        # decoder is the closest available independent reference; the native
        # decoder's measurement is recorded in CONTRIBUTING.md rather than dropped.
        Kind = 'amr'; Bitstream = 'amr-nb.amr'
        Decode = @('-c:a', 'libopencore_amrnb', '-f', 'amr'); ExpectedPackets = 401
    },
    [pscustomobject]@{
        Fixture = 'sip_rtp_amr_wb.pcap'; Sha256 = '1EAE7B3A42204F999592F323C5F351A21E0C48F5F51CFF03001D2E024D2672EA'
        Ssrc = 0x4C41594C; SrcIp = '192.0.2.20'; SrcPort = 40000
        Codec = 'AMR-WB'; Rate = 16000
        # Same reasoning as AMR-NB above.
        Kind = 'amr-wb'; Bitstream = 'amr-wb.awb'
        Decode = @('-c:a', 'libopencore_amrwb', '-f', 'amr'); ExpectedPackets = 400
    }
)

foreach ($case in $cases) {
    $fixturePath = Join-Path $fixtureDirFull $case.Fixture
    if (-not (Test-Path $fixturePath)) { throw "缺少夹具：$fixturePath" }
    $sha = (Get-FileHash -Algorithm SHA256 -Path $fixturePath).Hash
    if ($sha -ne $case.Sha256) { throw "$($case.Fixture) 的 SHA-256 与钉住的值不符：$sha" }

    Write-Host "== $($case.Fixture) / $($case.Codec) / SSRC $('0x{0:X8}' -f $case.Ssrc)"

    # --- 2.1 逐包导出负载（tshark，与本项目无关）---
    $filter = "rtp && ip.src==$($case.SrcIp) && udp.srcport==$($case.SrcPort)"
    $hexPath = Join-Path $workDir "$($case.Codec -replace '[^A-Za-z0-9]', '_').hex"
    & $TsharkPath -r $fixturePath -Y $filter -T fields -e rtp.payload 2>$null |
        Set-Content -Path $hexPath -Encoding ascii
    if ($LASTEXITCODE -ne 0) { throw "tshark 导出 $($case.Fixture) 失败" }
    $packets = (Get-Content -Path $hexPath | Where-Object { $_.Trim() -ne '' }).Count
    if ($packets -ne $case.ExpectedPackets) {
        throw "$($case.Fixture) 期望 $($case.ExpectedPackets) 个负载，实际 $packets"
    }
    Write-Host "   负载：$packets 包（tshark $filter）"

    # --- 2.2 还原成参考解码器认识的码流 ---
    $bitstreamPath = Join-Path $workDir $case.Bitstream
    # `amr-wb` 只是夹具侧的标签，helper 里 WB 是 `amr --wideband`。
    $helperCommand = if ($case.Kind -eq 'amr-wb') { 'amr' } else { $case.Kind }
    $helperArgs = @($helperCommand, '--hex', $hexPath, '--output', $bitstreamPath)
    if ($case.Kind -eq 'amr-wb') { $helperArgs += '--wideband' }
    & python $pythonHelper @helperArgs
    if ($LASTEXITCODE -ne 0) { throw "还原 $($case.Codec) 码流失败" }

    # --- 2.3 ffmpeg 解码 ---
    $pcmPath = Join-Path $workDir "$($case.Codec -replace '[^A-Za-z0-9]', '_').pcm"
    $ffmpegArgs = @('-hide_banner', '-loglevel', 'error', '-y') + $case.Decode +
        @('-i', $bitstreamPath, '-f', 's16le', '-ac', '1', $pcmPath)
    & $FfmpegPath @ffmpegArgs
    if ($LASTEXITCODE -ne 0) { throw "ffmpeg 解码 $($case.Codec) 失败" }

    # --- 2.4 裁到前 N 秒并写 golden ---
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($case.Fixture)
    $goldenPath = Join-Path $goldenDir "$stem.$($case.Ssrc).pcm"
    $samples = $Seconds * $case.Rate
    & python $pythonHelper trim --input $pcmPath --output $goldenPath --samples $samples
    if ($LASTEXITCODE -ne 0) { throw "裁剪 $($case.Codec) 失败" }

    $goldenSha = (Get-FileHash -Algorithm SHA256 -Path $goldenPath).Hash
    $totalSamples = (Get-Item $pcmPath).Length / 2
    Write-Host ("   参考：{0} 采样（{1:N3} s）→ golden {2} 采样，{3} 字节" -f `
        $totalSamples, ($totalSamples / $case.Rate), $samples, (Get-Item $goldenPath).Length)
    Write-Host "   SHA-256：$goldenSha"

    # --- 2.5 字节比较用的参考码流 ------------------------------------------
    # 只有「导出的容器/裸流 = 这条码流本身」的编码才有可比的参考：
    #   g729        裸流导出就是逐包负载的拼接
    #   AMR / AMR-WB `.amr`/`.awb` 就是 storage 格式帧的拼接
    # Opus 的 `.opus` 是 Ogg 容器，容器层的字节（serial、vendor、granule 映射）
    # 是封装器的选择而不是流数据，所以整体字节比较记为 N/A，理由写在 CONTRIBUTING.md。
    $byteReference = $null
    if ($case.Codec -eq 'g729') { $byteReference = "$stem.$($case.Ssrc).raw" }
    elseif ($case.Codec -eq 'AMR') { $byteReference = "$stem.$($case.Ssrc).amr" }
    elseif ($case.Codec -eq 'AMR-WB') { $byteReference = "$stem.$($case.Ssrc).awb" }
    if ($byteReference) {
        $referencePath = Join-Path $goldenDir $byteReference
        Copy-Item -Path $bitstreamPath -Destination $referencePath -Force
        Write-Host ("   字节比较参考：{0}（{1} 字节，SHA-256 {2}）" -f `
            $byteReference, (Get-Item $referencePath).Length,
            (Get-FileHash -Algorithm SHA256 -Path $referencePath).Hash)
    }
    Write-Host ''

    $generated += [pscustomobject]@{
        Fixture        = $case.Fixture
        Codec          = $case.Codec
        Ssrc           = $case.Ssrc
        Packets        = $packets
        Rate           = $case.Rate
        ReferenceTotal = $totalSamples
        GoldenSamples  = $samples
        Bytes          = (Get-Item $goldenPath).Length
        Sha256         = $goldenSha
    }
}

# ---- 3. 汇总（可直接粘进 CONTRIBUTING.md）--------------------------------------
Write-Host '| 夹具 | 编码 | SSRC | 负载包数 | 采样率 | 完整参考采样 | golden 采样 | 字节 | golden SHA-256 |'
Write-Host '|---|---|---:|---:|---:|---:|---:|---:|---|'
foreach ($row in $generated) {
    Write-Host ("| ``{0}`` | {1} | `0x{2:X8}` | {3} | {4} | {5} | {6} | {7} | ``{8}`` |" -f `
        $row.Fixture, $row.Codec, $row.Ssrc, $row.Packets, $row.Rate,
        $row.ReferenceTotal, $row.GoldenSamples, $row.Bytes, $row.Sha256)
}
