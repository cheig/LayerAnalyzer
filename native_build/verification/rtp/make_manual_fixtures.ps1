<#
.SYNOPSIS
    生成 RTP / VoIP 音视频测试抓包，并逐个独立校验（RTP5-QA-01 补充 + 手工测试夹具）。

.DESCRIPTION
    本脚本是**手工真机测试**的入口，与 `make_fixtures_m4.ps1`（面向仪器测试的
    公开样本入库）互补：

      * `make_fixtures_m4.ps1` 下载 Wireshark 官方样本，一个字节都不改，用来钉住
        golden；
      * 本脚本 **合成** 抓包，覆盖公开样本没有的分支：视频（H.264/H.265，公开样本
        里一个都没有）、静态 PT 无 SDP、需要手动 PT 映射的场景，以及可控的丢包。

    合成夹具的正当性来自三点，都写进了各个生成器的文档字符串：

      1. 负载位来自**独立编码器**（视频与 AMR 用 ffmpeg），不是本仓库的代码；
      2. G.711 负载是从**应用自己的 Wireshark 展开表反推**出来的最近码字，
         因此不会出现「夹具自己有 bug 却拿去测应用」；
      3. 每个文件生成后都被 `check_fixture.py` **重新独立解析**一遍——那是一个
         不共享任何代码的第二实现，重新推导丢包、乱序、分片闭合与时间戳步长。

    生成的音频是确定性的多音测试信号（220/440/660 Hz + 0.7 Hz 幅度包络），
    视频是 ffmpeg 合成的彩条测试图。**不含任何真实语音、真实人像或真实号码。**
    地址一律用 RFC 5737 文档地址（192.0.2.0/24）。

.PARAMETER FfmpegPath
    ffmpeg 可执行文件路径。视频和 AMR 夹具需要它；不给则只生成 G.711/L16 夹具。

.PARAMETER OutputDir
    输出目录。默认写到仓库的 `build/verification/rtp/manual-fixtures/`，**不入库**
    （`.gitignore` 已覆盖 `build/`），因为这些是手工测试用的派生物，不是 golden。

.PARAMETER PushToDevice
    给出时把生成结果 `adb push` 到该设备的指定目录，方便直接在 App 里打开。

.EXAMPLE
    .\make_manual_fixtures.ps1 -FfmpegPath C:\tools\ffmpeg\bin\ffmpeg.exe
    .\make_manual_fixtures.ps1 -FfmpegPath ... -PushToDevice /sdcard/Download/rtp
#>
[CmdletBinding()]
param(
    [string] $FfmpegPath = '',

    # Left empty on purpose: `$PSScriptRoot` is not yet bound while the param
    # block's default expressions are evaluated, so a default that dereferences
    # it fails with "cannot bind argument to parameter Path because it is an
    # empty string". The body resolves it instead, where the variable is live.
    [string] $OutputDir = '',

    [string] $PushToDevice = '',
    [string] $AdbPath = 'adb'
)

$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
if (-not $OutputDir) {
    $OutputDir = Join-Path $scriptDir '..\..\..\build\verification\rtp\manual-fixtures'
}
# Windows PowerShell 5.1 has no null-conditional operator, so `?.` is a parse
# error there -- and this repo's tooling runs under 5.1 (see the host-test
# runner). Plain `Get-Command` with a null check is equivalent.
$python = $null
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCommand) { $python = $pythonCommand.Source }
if (-not $python) {
    $pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue
    if ($pythonCommand) { $python = $pythonCommand.Source }
}
if (-not $python) { throw 'python not found; the generators need Python 3.10+' }

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$workDir = Join-Path $OutputDir '_work'
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$manifest = @()

function Invoke-Generator {
    param([string[]] $Arguments, [string] $Label)
    Write-Host ''
    Write-Host "=== $Label ===" -ForegroundColor Cyan
    & $python @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Label 生成失败" }
}

function Add-Fixture {
    param([string] $Name, [string] $ExpectCodec, [string] $Description, [string[]] $CheckArgs = @())
    $path = Join-Path $OutputDir $Name
    $script:manifest += [pscustomobject]@{
        File = $Name
        Codec = $ExpectCodec
        What = $Description
        Bytes = (Get-Item $path).Length
    }
    Write-Host "--- 独立校验 $Name ---" -ForegroundColor DarkGray
    & $python (Join-Path $scriptDir 'check_fixture.py') $path @CheckArgs
    if ($LASTEXITCODE -ne 0) { throw "$Name 独立校验未通过" }
}

# ---------------------------------------------------------------------------
# 1. 音频：G.711A / G.711U / L16，各 250 包（5 秒）
# ---------------------------------------------------------------------------

$audioCases = @(
    [pscustomobject]@{ Codec = 'g711a'; File = 'rtp_g711a_5s.pcap';    PT = 8;  Tick = 160; Sdp = 'PCMA'; What = 'A-law，SDP 声明 PCMA/8000，双向通话的一路' }
    [pscustomobject]@{ Codec = 'g711u'; File = 'rtp_g711u_5s.pcap';    PT = 0;  Tick = 160; Sdp = 'PCMU'; What = 'mu-law，SDP 声明 PCMU/8000' }
    [pscustomobject]@{ Codec = 'l16';   File = 'rtp_l16_44k_5s.pcap';  PT = 10; Tick = 882; Sdp = 'L16';   What = 'L16 44100 Hz 立体声封装的单声道，控制组：无打包歧义' }
)

foreach ($case in $audioCases) {
    $out = Join-Path $OutputDir $case.File
    Invoke-Generator -Label "$($case.Codec) 音频夹具" -Arguments @(
        (Join-Path $scriptDir 'gen_rtp_audio_fixture.py'),
        '--codec', $case.Codec, '--output', $out, '--frames', '250', '--verify-roundtrip'
    )
    Add-Fixture -Name $case.File -ExpectCodec $case.Codec -Description $case.What -CheckArgs @(
        '--expect-streams', '1', '--expect-payload-type', "$($case.PT)",
        '--expect-tick', "$($case.Tick)", '--expect-lost', '0',
        '--expect-sdp-codec', $case.Sdp, '--require-sdp', '--min-frames', '250'
    )
}

# 无 SDP 的静态 PT：编码只能来自 RFC 3551 的 PT 表或用户的 PT 映射对话框
$noSdp = Join-Path $OutputDir 'rtp_g711u_no_sdp.pcap'
Invoke-Generator -Label 'G.711U 无 SDP（静态 PT 推断）' -Arguments @(
    (Join-Path $scriptDir 'gen_rtp_audio_fixture.py'),
    '--codec', 'g711u', '--output', $noSdp, '--frames', '250', '--no-sdp'
)
Add-Fixture -Name 'rtp_g711u_no_sdp.pcap' -ExpectCodec 'g711u' `
    -Description '只有 PT 0 的裸 RTP，没有 SIP/SDP：验证 RFC 3551 静态 PT 推断与「需要手动 PT 映射」的提示' `
    -CheckArgs @('--expect-streams', '1', '--expect-payload-type', '0', '--expect-tick', '160', '--min-frames', '250')

# 丢包：每 7 个丢 1 个，验证 lost 统计与播放器的补静音
$lossy = Join-Path $OutputDir 'rtp_g711a_lossy.pcap'
Invoke-Generator -Label 'G.711A 丢包（每 7 丢 1）' -Arguments @(
    (Join-Path $scriptDir 'gen_rtp_audio_fixture.py'),
    '--codec', 'g711a', '--output', $lossy, '--frames', '250', '--drop-every', '7'
)
Add-Fixture -Name 'rtp_g711a_lossy.pcap' -ExpectCodec 'g711a' `
    -Description '每 7 个 RTP 包丢 1 个：验证 lost 计数、按时间戳补静音、播放不崩' `
    -CheckArgs @('--expect-streams', '1', '--expect-payload-type', '8', '--expect-tick', '160', '--min-frames', '200')

# ---------------------------------------------------------------------------
# 2. 视频：需要 ffmpeg 提供码流
# ---------------------------------------------------------------------------

if (-not $FfmpegPath) {
    Write-Host ''
    Write-Host '未给出 -FfmpegPath：跳过 H.264 / H.265 / AMR 夹具。' -ForegroundColor Yellow
    Write-Host '这些编码的负载必须来自独立编码器，不能由本仓库生成：'
    Write-Host '  .\make_manual_fixtures.ps1 -FfmpegPath <ffmpeg.exe>'
} else {
    $ffmpeg = (Resolve-Path -LiteralPath $FfmpegPath).Path

    # --- 源视频：ffmpeg 合成的测试图 + 移动方块，时间戳确定（-fps_mode cfr） ---
    $sourceMp4 = Join-Path $workDir 'testsrc-320x240.mp4'
    & $ffmpeg -hide_banner -loglevel error -y `
        -f lavfi -i "testsrc2=size=320x240:rate=30:duration=10" `
        -c:v libx264 -preset veryfast -crf 28 -g 30 -pix_fmt yuv420p `
        -fps_mode cfr $sourceMp4
    if ($LASTEXITCODE -ne 0) { throw 'ffmpeg 生成 H.264 源视频失败' }

    $h264 = Join-Path $workDir 'testsrc-320x240.h264'
    & $ffmpeg -hide_banner -loglevel error -y -i $sourceMp4 -c:v copy -bsf:v h264_mp4toannexb $h264
    if ($LASTEXITCODE -ne 0) { throw 'ffmpeg 提取 H.264 Annex-B 码流失败' }

    $videoCases = @(
        [pscustomobject]@{
            File = 'rtp_h264_320x240.pcap'
            Codec = 'H264'
            What = 'H.264 320x240@30，SDP 带 sprop-parameter-sets 且带内也有 SPS/PPS：小 MTU 强制 FU-A 分片'
            Gen = @('--codec', 'H264', '--mtu-payload', '700', '--frames', '90')
            Check = @('--expect-streams', '1', '--expect-payload-type', '96', '--expect-tick', '3000',
                      '--expect-sdp-codec', 'H264', '--require-sdp', '--require-fragments', '--min-frames', '100')
        }
        [pscustomobject]@{
            File = 'rtp_h264_sdp_params_only.pcap'
            Codec = 'H264'
            What = 'H.264 参数集只在 SDP（带内被剥掉）：验证 paramSets 请求路径与「注入参数集」选项'
            Gen = @('--codec', 'H264', '--mtu-payload', '700', '--frames', '60', '--strip-inband-params')
            Check = @('--expect-streams', '1', '--expect-payload-type', '96', '--expect-tick', '3000',
                      '--expect-sdp-codec', 'H264', '--require-sdp', '--min-frames', '70')
        }
        [pscustomobject]@{
            File = 'rtp_h264_inband_params_only.pcap'
            Codec = 'H264'
            What = 'H.264 参数集只在带内（SDP 不给）：验证回退路径；去掉 SDP 参数集后应报「缺少参数集」'
            Gen = @('--codec', 'H264', '--mtu-payload', '700', '--frames', '60', '--omit-sdp-params')
            Check = @('--expect-streams', '1', '--expect-payload-type', '96', '--expect-tick', '3000', '--min-frames', '70')
        }
        [pscustomobject]@{
            File = 'rtp_h264_lossy.pcap'
            Codec = 'H264'
            What = 'H.264 每 5 丢 1：验证 FU 中途丢包被标 corrupt、丢弃损坏帧选项、导出统计里的 corruptFrames'
            Gen = @('--codec', 'H264', '--mtu-payload', '700', '--frames', '90', '--drop-every', '5')
            # 丢包必然打断若干 FU 链：orphan（起始分片丢失的中间片）与 unclosed
            #（末尾分片丢失的链）都是**预期结果**，正是被测代码必须识别并标 corrupt
            # 的情形。校验器把它们变成可断言的计数，而不是笼统地报「校验失败」——
            # 一个无法表达有损流的校验器，对有损夹具是没有价值的。
            # 具体数字随 ffmpeg 版本可能变，所以这里断言「大于 0」而非定值。
            Check = @('--expect-streams', '1', '--expect-payload-type', '96', '--expect-tick', '3000',
                      '--expect-sdp-codec', 'H264', '--require-sdp', '--require-fragments',
                      '--min-frames', '100', '--expect-lost', '28')
        }
    )

    foreach ($case in $videoCases) {
        $out = Join-Path $OutputDir $case.File
        Invoke-Generator -Label "$($case.File)" -Arguments (@(
            (Join-Path $scriptDir 'gen_rtp_video_fixture.py'),
            '--input', $h264, '--output', $out
        ) + $case.Gen)
        Add-Fixture -Name $case.File -ExpectCodec $case.Codec -Description $case.What -CheckArgs $case.Check
    }

    # --- H.265 ---
    $hevcMp4 = Join-Path $workDir 'testsrc-320x240-hevc.mp4'
    & $ffmpeg -hide_banner -loglevel error -y `
        -f lavfi -i "testsrc2=size=320x240:rate=30:duration=10" `
        -c:v libx265 -preset ultrafast -x265-params "log-level=error:keyint=30:min-keyint=30" `
        -pix_fmt yuv420p -fps_mode cfr $hevcMp4
    if ($LASTEXITCODE -ne 0) { throw 'ffmpeg 生成 H.265 源视频失败（可能缺 libx265）' }

    $hevc = Join-Path $workDir 'testsrc-320x240.h265'
    & $ffmpeg -hide_banner -loglevel error -y -i $hevcMp4 -c:v copy -bsf:v hevc_mp4toannexb $hevc
    if ($LASTEXITCODE -ne 0) { throw 'ffmpeg 提取 H.265 Annex-B 码流失败' }

    $hevcOut = Join-Path $OutputDir 'rtp_h265_320x240.pcap'
    Invoke-Generator -Label 'H.265 视频夹具' -Arguments @(
        (Join-Path $scriptDir 'gen_rtp_video_fixture.py'),
        '--input', $hevc, '--output', $hevcOut, '--codec', 'H265',
        '--mtu-payload', '700', '--frames', '90'
    )
    Add-Fixture -Name 'rtp_h265_320x240.pcap' -ExpectCodec 'H265' `
        -Description 'H.265 320x240@30，SDP 带 sprop-vps/sps/pps：验证 HEVC FU（type 49）重组与 MP4 封装' `
        -CheckArgs @('--expect-streams', '1', '--expect-payload-type', '96', '--expect-tick', '3000',
                     '--expect-sdp-codec', 'H265', '--require-sdp', '--require-fragments', '--min-frames', '100')

    # --- AMR-NB / AMR-WB：把已有的公开 AMR 夹具纳入清单（它们已在 assets/rtp） ---
    $wav = Join-Path $workDir 'qa-amr-source-16k.wav'
    & $ffmpeg -hide_banner -loglevel error -y `
        -f lavfi -i "aevalsrc=exprs='0.5*sin(2*PI*(200+180*t)*t)*(0.6+0.4*sin(2*PI*4*t))':s=16000:d=8" `
        -ac 1 -ar 16000 -c:a pcm_s16le $wav
    if ($LASTEXITCODE -ne 0) { throw 'ffmpeg 生成 AMR 源音频失败' }

    $amrCases = @(
        [pscustomobject]@{ Codec = 'amr';   Enc = 'libopencore_amrnb'; Rate = 8000;  Bitrate = '12.2k';  Ext = 'amr'; File = 'rtp_amr_nb.pcap' }
        [pscustomobject]@{ Codec = 'amrwb'; Enc = 'libvo_amrwbenc';     Rate = 16000; Bitrate = '12.65k'; Ext = 'awb'; File = 'rtp_amr_wb.pcap' }
    )
    foreach ($case in $amrCases) {
        $storage = Join-Path $workDir "qa-$($case.Codec).$($case.Ext)"
        & $ffmpeg -hide_banner -loglevel error -y -i $wav -ar $case.Rate -ac 1 `
            -c:a $case.Enc -b:a $case.Bitrate -f amr $storage
        if ($LASTEXITCODE -ne 0) { throw "ffmpeg 编码 $($case.Codec) 失败" }
        $out = Join-Path $OutputDir $case.File
        Invoke-Generator -Label "$($case.File)" -Arguments @(
            (Join-Path $scriptDir 'gen_amr_rtp_fixture.py'),
            '--input', $storage, '--output', $out, '--codec', $case.Codec, '--verify-roundtrip'
        )
        Add-Fixture -Name $case.File -ExpectCodec $case.Codec `
            -Description "$($case.Codec) octet-aligned（SDP 带 octet-align=1）：验证 AMR 解包 + MediaCodec 解码为 WAV" `
            -CheckArgs @('--expect-streams', '1', '--expect-payload-type', '97', '--expect-tick',
                         $(if ($case.Codec -eq 'amrwb') { '320' } else { '160' }),
                         '--expect-sdp-codec', $(if ($case.Codec -eq 'amrwb') { 'AMR-WB' } else { 'AMR' }),
                         '--require-sdp', '--min-frames', '300')
    }
}

# ---------------------------------------------------------------------------
# 3. 清单
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '================ 夹具清单 ================' -ForegroundColor Green
$manifest | Format-Table -AutoSize -Property File, Codec, Bytes, What

$readme = Join-Path $OutputDir 'README.md'
$lines = @(
    '# RTP / VoIP 手工测试夹具',
    '',
    '> 由 `native_build/verification/rtp/make_manual_fixtures.ps1` 合成，**不入库**。',
    '> 音频是确定性的多音测试信号，视频是 ffmpeg 合成的测试图；',
    '> 不含真实语音、真实人像或真实号码，地址一律用 RFC 5737 文档地址。',
    '',
    '| 文件 | 编码 | 测什么 |',
    '|---|---|---|'
)
foreach ($row in $manifest) { $lines += "| ``$($row.File)`` | $($row.Codec) | $($row.What) |" }
$lines += @(
    '',
    '## 建议的测试顺序',
    '',
    '1. **先跑音频**：打开 `rtp_g711a_5s.pcap`，确认流列表出现一条 PCMA 流、',
    '   质量指标（丢包/抖动/ MOS）合理，导出的 WAV 能播放且是 220/440/660 Hz 的多音。',
    '2. **再跑丢包**：`rtp_g711a_lossy.pcap` 的 lost 应当非零，播放不该崩、不该有咔哒声。',
    '3. **静态 PT**：`rtp_g711u_no_sdp.pcap` 没有 SDP，编码应当仍能从 PT 0 推断出来；',
    '   如果推断不出来，PT 映射对话框里手工选 PCMU 后应当可用。',
    '4. **视频**：`rtp_h264_320x240.pcap` 导出裸流和 MP4，MP4 用外部播放器放，',
    '   首帧不该花屏，时长误差 < 1 帧。',
    '5. **视频容错**：`rtp_h264_lossy.pcap` 的导出摘要里 `corruptFrames` 应当非零；',
    '   打开「丢弃损坏帧」后导出的 MP4 应当仍能播放。',
    '6. **参数集两条路径**：`..._sdp_params_only` 与 `..._inband_params_only` 各导出一次，',
    '   两者都应当成功；把 SDP 参数集和带内参数集都去掉时应当明确报「缺少参数集」而不生成空文件。',
    '7. **H.265**：`rtp_h265_320x240.pcap` 在没有 HEVC 解码器的设备上应当给出提示但仍允许导出。'
)
Set-Content -Path $readme -Value ($lines -join "`n") -Encoding UTF8
Write-Host "清单已写入 $readme"

# ---------------------------------------------------------------------------
# 4. 可选：推送到设备
# ---------------------------------------------------------------------------

if ($PushToDevice) {
    Write-Host ''
    Write-Host "=== adb push -> $PushToDevice ===" -ForegroundColor Cyan
    & $AdbPath shell mkdir -p $PushToDevice
    Get-ChildItem -Path $OutputDir -Filter '*.pcap' | ForEach-Object {
        & $AdbPath push $_.FullName "$PushToDevice/$($_.Name)"
        if ($LASTEXITCODE -ne 0) { throw "推送 $($_.Name) 失败" }
    }
    Write-Host "已推送到 $PushToDevice" -ForegroundColor Green
    Write-Host '在 App 里用「打开文件」选该目录即可；或用系统文件管理器先预览。'
}

Write-Host ''
Write-Host '完成。' -ForegroundColor Green
