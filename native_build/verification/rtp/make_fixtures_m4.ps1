<#
.SYNOPSIS
    取得 RTP4-QA-01 的公开 RTP 样本（G.722 / G.726 / G.729 / Opus / iLBC）。

.DESCRIPTION
    源样本全部来自 Wireshark 官方 SampleCaptures wiki 的 "SIP and RTP" 一节
    （SIPp <-> FreeSWITCH 1.6.12 实验室测试台）。脚本只做「下载 + 校验 + 改名 + 入库」，
    不改动一个字节，所以本地 SHA-256 与来源 SHA-256 相同。

    AMR-NB / AMR-WB 的夹具**不在这里**：公开样本里没有可用的 AMR RTP 抓包
    （`Mobile-Originating-Call(AMR).pcap` 是 Iu-CS 承载，RTP 负载是 IuUP 帧而不是 AMR
    帧，需要 IuUP 解帧才能用），所以它们由 `gen_amr_rtp_fixture.py` 生成，见 CONTRIBUTING.md。

.NOTES
    来源、许可证、隐私核对记录见 CONTRIBUTING.md；
    参考音频生成见同目录 make_golden_m4.ps1，说明见 CONTRIBUTING.md。
#>
[CmdletBinding()]
param(
    # 下载缓存目录，默认 $env:TEMP\layanalyzer-rtp-m4
    [string] $DownloadDir = (Join-Path $env:TEMP 'layanalyzer-rtp-m4'),

    # 输出目录，默认写入 androidTest 资产目录
    [string] $OutputDir = (Join-Path $PSScriptRoot '..\..\..\app\src\androidTest\assets\rtp'),

    # ffmpeg 可执行文件；给出时才生成 AMR-NB / AMR-WB 夹具
    [string] $FfmpegPath = ''
)

$ErrorActionPreference = 'Stop'

$baseUrl = 'https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures'

# 来源文件名 -> (本地文件名, 来源/本地 SHA-256)
$fixtures = @(
    [pscustomobject]@{
        Source = 'sip-rtp-g722.pcap'
        Local  = 'sip_rtp_g722.pcap'
        Sha256 = '838639FE064DF7B4076EFEC319CA80EE124D8D4C9118B1CC929524121C361413'
    },
    [pscustomobject]@{
        Source = 'sip-rtp-g726.pcap'
        Local  = 'sip_rtp_g726.pcap'
        Sha256 = '89282263E575CF1497342A1B38586E6FCCED32CB15E21B798748A49D8DAB545F'
    },
    [pscustomobject]@{
        Source = 'sip-rtp-g729a.pcap'
        Local  = 'sip_rtp_g729.pcap'
        Sha256 = '8573F2F7ADF019E743A8C41D9146DF256C67AFDD66169A64323B61EDAA55476A'
    },
    [pscustomobject]@{
        Source = 'sip-rtp-opus.pcap'
        Local  = 'sip_rtp_opus.pcap'
        Sha256 = 'C8920238EDCC96188047812A05E9D2CE84A4094529A3434FEA1EA3D92B713FDE'
    },
    [pscustomobject]@{
        Source = 'sip-rtp-ilbc.pcap'
        Local  = 'sip_rtp_ilbc.pcap'
        Sha256 = '65E313EE78429C829B9B5C7D86975812F8C1F9C7EA06DC3888C900EFB013F9B8'
    }
)

New-Item -ItemType Directory -Force -Path $DownloadDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

foreach ($fixture in $fixtures) {
    $target = Join-Path $OutputDir $fixture.Local
    if (Test-Path $target) {
        $existing = (Get-FileHash -Algorithm SHA256 -Path $target).Hash
        if ($existing -eq $fixture.Sha256) {
            Write-Host "已存在且校验通过：$($fixture.Local)"
            continue
        }
        throw "已存在的 $($fixture.Local) 与钉住的 SHA-256 不符：$existing"
    }

    $cached = Join-Path $DownloadDir $fixture.Source
    if (-not (Test-Path $cached)) {
        $url = "$baseUrl/$($fixture.Source)"
        Write-Host "下载：$url"
        Invoke-WebRequest -Uri $url -OutFile $cached -UseBasicParsing
    }

    $sha = (Get-FileHash -Algorithm SHA256 -Path $cached).Hash
    if ($sha -ne $fixture.Sha256) {
        throw "源样本 $($fixture.Source) 的 SHA-256 不匹配：$sha"
    }
    Copy-Item -Path $cached -Destination $target
    Write-Host "入库：$($fixture.Local)  $sha"
}

Write-Host ''
Write-Host '公开样本处理完成。'

if (-not $FfmpegPath) {
    Write-Host ''
    Write-Host '未给出 -FfmpegPath，跳过 AMR-NB / AMR-WB 夹具的生成。'
    Write-Host '给出 ffmpeg 路径后这两个夹具会在本机重新生成：'
    Write-Host '  .\native_build\verification\rtp\make_fixtures_m4.ps1 -FfmpegPath <ffmpeg.exe>'
    exit 0
}

# ---- AMR-NB / AMR-WB -------------------------------------------------------
#
# 公开样本里没有可用的 AMR RTP 抓包（见 CONTRIBUTING.md），所以这两个夹具由
# ffmpeg 编码 + gen_amr_rtp_fixture.py 打包生成：
#
#   1. ffmpeg 合成一段确定性的测试信号（啁啾 + 幅度调制，每 20 ms 帧都不相同，
#      便于发现帧序或时序错误）；
#   2. ffmpeg 的 libopencore_amrnb / libvo_amrwbenc 编码成 AMR storage 格式；
#   3. gen_amr_rtp_fixture.py 逐帧打包成 octet-aligned RTP + 最小的 SIP/SDP 呼叫。
#
# 信号是合成的，不含任何真实语音或身份信息。
$ffmpeg = (Resolve-Path -LiteralPath $FfmpegPath).Path
$workDir = Join-Path $DownloadDir 'amr'
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$sourceWav = Join-Path $workDir 'qa01-source-16k.wav'

& $ffmpeg -hide_banner -loglevel error -y `
    -f lavfi -i "aevalsrc=exprs='0.5*sin(2*PI*(200+180*t)*t)*(0.6+0.4*sin(2*PI*4*t))':s=16000:d=8" `
    -ac 1 -ar 16000 -c:a pcm_s16le $sourceWav
if ($LASTEXITCODE -ne 0) { throw 'ffmpeg 生成测试信号失败' }

$amrCases = @(
    [pscustomobject]@{
        Codec       = 'amr'
        Encoder     = 'libopencore_amrnb'
        Bitrate     = '12.2k'
        Rate        = 8000
        Storage     = (Join-Path $workDir 'qa01-amr-nb.amr')
        Local       = 'sip_rtp_amr_nb.pcap'
        Sha256      = '4C190FF6B9BB681B794B6EDFB5822DB38EB530C5BF246C30E8B6C5D75807B7A0'
    },
    [pscustomobject]@{
        Codec       = 'amrwb'
        Encoder     = 'libvo_amrwbenc'
        Bitrate     = '12.65k'
        Rate        = 16000
        Storage     = (Join-Path $workDir 'qa01-amr-wb.awb')
        Local       = 'sip_rtp_amr_wb.pcap'
        Sha256      = '1EAE7B3A42204F999592F323C5F351A21E0C48F5F51CFF03001D2E024D2672EA'
    }
)

foreach ($case in $amrCases) {
    & $ffmpeg -hide_banner -loglevel error -y -i $sourceWav -ar $case.Rate -ac 1 `
        -c:a $case.Encoder -b:a $case.Bitrate -f amr $case.Storage
    if ($LASTEXITCODE -ne 0) { throw "ffmpeg 编码 $($case.Codec) 失败" }

    $target = Join-Path $OutputDir $case.Local
    python (Join-Path $PSScriptRoot 'gen_amr_rtp_fixture.py') `
        --input $case.Storage --output $target --codec $case.Codec --verify-roundtrip
    if ($LASTEXITCODE -ne 0) { throw "生成 $($case.Local) 失败" }

    $sha = (Get-FileHash -Algorithm SHA256 -Path $target).Hash
    Write-Host "入库：$($case.Local)  $sha"
    if ($case.Sha256 -ne 'PENDING' -and $sha -ne $case.Sha256) {
        throw "$($case.Local) 的 SHA-256 与钉住的值不符：$sha"
    }
}

