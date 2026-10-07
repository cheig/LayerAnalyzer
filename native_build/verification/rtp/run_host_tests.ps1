<#
.SYNOPSIS
    编译并运行 RTP 纯算法代码的 host 单测（RTP1-ARCH-03）。

.DESCRIPTION
    在开发机上直接编译 app/src/main/cpp/layanalyzer/rtp/ 下不依赖 epan 的纯算法源文件
    （core/、codecs/、depack/、io/，见 host_tests/CMakeLists.txt 的 RTP_HOST_SOURCES），
    跑 host_tests/ 下的 doctest 用例。不需要 Android 设备、NDK 或 Gradle。

    工具链按下面的顺序探测，用第一个「能配置且能构建」的：
      1. cl（VS Build Tools）：cl 不在 PATH 时用 vswhere 找 vcvars64.bat 导入环境；生成器 Ninja / NMake
      2. clang++ + Ninja
      3. g++（TDM-GCC / MinGW-w64）+ Ninja 或 MinGW Makefiles
      4. WSL 里的 cmake && make
    cmake（3.22+）与 ninja 先在 PATH 里找，再退到 VS 自带目录与 Android SDK 的 cmake 目录。

    一个工具链都没找到时，打印安装指引并以退出码 1 结束（不会静默跳过）。配置/编译失败的
    完整输出同时留在控制台和 $env:TEMP\rtp_host_tests\ 下，不会被吞掉。

    脚本**不联网**：doctest.h 与 LICENSE.txt 已入库在 host_tests/。

.PARAMETER Test
    doctest 的用例过滤器，支持通配符，可以给多个；等价于 doctest 的 --test-case=。
        .\run_host_tests.ps1 -Test "RtpStreamKey*"
        .\run_host_tests.ps1 -Test "RtpStreamAnalysis*","RtpDecodability*"
    没匹配到任何用例时脚本返回 1（doctest 自己会返回 0，空跑不算通过）。

.PARAMETER Clean
    构建前删除构建目录（host_tests\build）。

.PARAMETER PathOnly
    只在 PATH 里查找工具链：不做 vswhere / 已知安装目录的兜底探测，也不使用 WSL。
    CI 里固定工具链时用；也可以用来复现「机器上没有编译器」时的提示。

.EXAMPLE
    .\run_host_tests.ps1

.NOTES
    构建目录：native_build/verification/rtp/host_tests/build（已加入 .gitignore）。
    被测源文件与用例的登记方式见 host_tests/CMakeLists.txt；用法说明见 CONTRIBUTING.md。
#>
[CmdletBinding()]
param(
    [string[]] $Test,
    [switch] $Clean,
    [switch] $PathOnly
)

$ErrorActionPreference = 'Stop'
# 原生命令的失败要看 $LASTEXITCODE：不要让它变成异常，否则没法依次退到下一个工具链。
if (Test-Path Variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$RepoRoot   = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$SourceDir  = Join-Path $PSScriptRoot 'host_tests'
$BuildDir   = Join-Path $SourceDir 'build'
$ExeName    = 'rtp_host_tests'
$LogDir     = Join-Path $env:TEMP 'rtp_host_tests'

$script:Probe = New-Object System.Collections.ArrayList

function Write-Step {
    param([string] $Message)
    Write-Host ("[run_host_tests] {0}" -f $Message)
}

function Add-Probe {
    param([string] $Name, [string] $Value)
    if (-not $Value) { $Value = '未找到' }
    [void]$script:Probe.Add(('{0,-12} {1}' -f ($Name + ':'), $Value))
}

function Get-CommandPath {
    param([string[]] $Names)
    foreach ($name in $Names) {
        $cmd = Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source)) { return $cmd.Source }
    }
    return $null
}

# 直接扫 PATH：Get-Command 在同一个进程里有命令缓存，导入 vcvars 之后用它判断不可靠。
function Find-OnPath {
    param([string] $FileName)
    foreach ($entry in ($env:PATH -split ';')) {
        if (-not $entry) { continue }
        $candidate = Join-Path $entry.Trim() $FileName
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

# PATH 优先，其次已知安装目录（-PathOnly 时只看 PATH）。
function Resolve-Tool {
    param([string[]] $Names, [string[]] $KnownPaths = @())
    $found = Get-CommandPath -Names $Names
    if ($found) { return $found }
    if (-not $PathOnly) {
        foreach ($path in $KnownPaths) {
            if ($path -and (Test-Path -LiteralPath $path)) { return $path }
        }
    }
    return $null
}

function Add-DirToPath {
    param([string] $Directory)
    if (-not $Directory) { return }
    if (-not (Test-Path -LiteralPath $Directory)) { return }
    $dir = ([System.IO.Path]::GetFullPath($Directory)).TrimEnd('\')
    foreach ($entry in ($env:PATH -split ';')) {
        if (-not $entry) { continue }
        try {
            if (([System.IO.Path]::GetFullPath($entry)).TrimEnd('\') -ieq $dir) { return }
        }
        catch { }
    }
    $env:PATH = "$dir;$env:PATH"
}

# vcvars64.bat 只能在 cmd.exe 里执行；用它跑一次 `set` 把结果环境变量搬进本进程。
function Import-VcVarsEnvironment {
    param([string] $VcVarsPath)
    $lines = & cmd.exe /c ('call "{0}" >nul 2>&1 && set' -f $VcVarsPath)
    if ($LASTEXITCODE -ne 0 -or -not $lines) { throw "vcvars64.bat 执行失败：$VcVarsPath" }
    foreach ($line in $lines) {
        $index = $line.IndexOf('=')
        if ($index -gt 0) {
            Set-Item -Path ('env:' + $line.Substring(0, $index)) -Value $line.Substring($index + 1)
        }
    }
    if (-not (Find-OnPath -FileName 'cl.exe')) { throw "导入 vcvars 环境后仍找不到 cl：$VcVarsPath" }
}

function ConvertTo-WslPath {
    param([string] $WindowsPath)
    $full = [System.IO.Path]::GetFullPath($WindowsPath)
    if ($full -match '^([A-Za-z]):\\(.*)$') {
        return '/mnt/' + $Matches[1].ToLowerInvariant() + '/' + ($Matches[2] -replace '\\', '/')
    }
    throw "无法把路径转成 WSL 形式：$WindowsPath"
}

if (-not (Test-Path -LiteralPath (Join-Path $SourceDir 'CMakeLists.txt'))) {
    throw "找不到 host 单测工程：$SourceDir"
}

# ---- 1. cmake（3.22+）与 ninja 的位置 --------------------------------------
$sdkDir = $null
foreach ($candidate in @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT)) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) { $sdkDir = $candidate; break }
}
if (-not $sdkDir) {
    $localProperties = Join-Path $RepoRoot 'local.properties'
    if (Test-Path -LiteralPath $localProperties) {
        foreach ($line in Get-Content -LiteralPath $localProperties) {
            if ($line -match '^\s*sdk\.dir\s*=\s*(.+?)\s*$') {
                # Java properties 转义：I\:\\SDK -> I:\SDK
                $value = $Matches[1].Replace('\\', '\').Replace('\:', ':')
                if (Test-Path -LiteralPath $value) { $sdkDir = $value; break }
            }
        }
    }
}

$sdkCmake = @()
$sdkNinja = @()
$sdkCmakeRoot = $null
if ($sdkDir) { $sdkCmakeRoot = Join-Path $sdkDir 'cmake' }
if ($sdkCmakeRoot -and (Test-Path -LiteralPath $sdkCmakeRoot)) {
    $sdkVersions = Get-ChildItem -LiteralPath $sdkCmakeRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object -Property Name -Descending
    foreach ($version in $sdkVersions) {
        $sdkCmake += (Join-Path $version.FullName 'bin\cmake.exe')
        $sdkNinja += (Join-Path $version.FullName 'bin\ninja.exe')
    }
}

# ---- 2. Visual Studio：vswhere -> vcvars64 / 自带 cmake+ninja ---------------
$vsRoot = $null
$vcvars64 = $null
$vsCmake = $null
$vsNinja = $null
if (-not $PathOnly) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $vsRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null | Select-Object -First 1
        if ($vsRoot) {
            $vsRoot = $vsRoot.Trim()
            $vcvars64 = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
            $vsCmake = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
            $vsNinja = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
        }
    }
}

# ---- 3. 编译器 -------------------------------------------------------------
$cmake = Resolve-Tool -Names @('cmake') -KnownPaths (@($vsCmake) + $sdkCmake)
$ninja = Resolve-Tool -Names @('ninja') -KnownPaths (@($vsNinja) + $sdkNinja)
$cl = Get-CommandPath -Names @('cl')
$clang = Resolve-Tool -Names @('clang++', 'clang++.exe') -KnownPaths @(
    'C:\Program Files\LLVM\bin\clang++.exe',
    'C:\Program Files (x86)\LLVM\bin\clang++.exe')
$gxx = Resolve-Tool -Names @('g++', 'g++.exe') -KnownPaths @(
    'C:\TDM-GCC-64\bin\g++.exe',
    'C:\MinGW\bin\g++.exe',
    'C:\msys64\mingw64\bin\g++.exe',
    'C:\ProgramData\mingw64\mingw64\bin\g++.exe',
    'C:\tools\msys64\mingw64\bin\g++.exe')

$makeKnown = @()
if ($gxx) {
    $gxxDir = Split-Path -Parent $gxx
    $makeKnown = @((Join-Path $gxxDir 'mingw32-make.exe'), (Join-Path $gxxDir 'make.exe'))
}
$make = Resolve-Tool -Names @('make', 'mingw32-make', 'mingw32-make.exe') -KnownPaths $makeKnown

Add-Probe 'cmake' $cmake
Add-Probe 'ninja' $ninja
Add-Probe 'make' $make
Add-Probe 'cl' $cl
Add-Probe 'vcvars64' $vcvars64
Add-Probe 'clang++' $clang
Add-Probe 'g++' $gxx

# ---- 4. 候选工具链（顺序即重试顺序）----------------------------------------
$candidates = New-Object System.Collections.ArrayList

if ($cmake) {
    # 4.1 MSVC：生成器 Ninja 优先，其次 NMake；cl 不在 PATH 时靠 vcvars64.bat 带进来。
    $msvcGenerator = $null
    if ($ninja) { $msvcGenerator = 'Ninja' }
    elseif ($vsRoot) { $msvcGenerator = 'NMake Makefiles' }
    if ($msvcGenerator) {
        $msvcVcVars = $null
        if (-not $cl -and $vcvars64 -and (Test-Path -LiteralPath $vcvars64)) { $msvcVcVars = $vcvars64 }
        if ($cl -or $msvcVcVars) {
            [void]$candidates.Add([pscustomobject]@{
                    Kind = 'windows'
                    Name = "MSVC (cl) + $msvcGenerator"
                    Cmake = $cmake
                    Generator = $msvcGenerator
                    Compiler = $cl
                    VcVars = $msvcVcVars
                    Ninja = $ninja
                    Make = $null
                })
        }
    }

    # 4.2 clang++ + Ninja。Windows 上的 clang 默认调 MSVC 的 link.exe，没有 VS 环境时链接会失败，
    #     所以有 vcvars 就一并导入。
    if ($clang -and $ninja) {
        $clangVcVars = $null
        if ((-not $PathOnly) -and $vcvars64 -and (Test-Path -LiteralPath $vcvars64) -and
            (-not (Get-CommandPath -Names @('link')))) {
            $clangVcVars = $vcvars64
        }
        [void]$candidates.Add([pscustomobject]@{
                Kind = 'windows'
                Name = 'clang++ + Ninja'
                Cmake = $cmake
                Generator = 'Ninja'
                Compiler = $clang
                VcVars = $clangVcVars
                Ninja = $ninja
                Make = $null
            })
    }

    # 4.3 g++：同目录下的 mingw32-make 作为 MinGW Makefiles 的 make 程序。
    if ($gxx) {
        $gccGenerator = $null
        $gccMake = $null
        if ($ninja) { $gccGenerator = 'Ninja' }
        elseif ($make) { $gccGenerator = 'MinGW Makefiles'; $gccMake = $make }
        if ($gccGenerator) {
            [void]$candidates.Add([pscustomobject]@{
                    Kind = 'windows'
                    Name = "g++ + $gccGenerator"
                    Cmake = $cmake
                    Generator = $gccGenerator
                    Compiler = $gxx
                    VcVars = $null
                    Ninja = $ninja
                    Make = $gccMake
                })
        }
    }
}

# 4.4 WSL（最后兜底）
$wsl = $null
if (-not $PathOnly) {
    $wsl = Get-CommandPath -Names @('wsl')
    if ($wsl) {
        [void]$candidates.Add([pscustomobject]@{
                Kind = 'wsl'
                Name = 'WSL (cmake + make)'
                Cmake = $null
                Generator = 'Unix Makefiles'
                Compiler = $null
                VcVars = $null
                Ninja = $null
                Make = $null
            })
    }
}
Add-Probe 'wsl' $wsl

# ---- 5. 一个工具链都没有：给安装指引，退出码 1 ------------------------------
if ($candidates.Count -eq 0) {
    Write-Host ''
    Write-Host '未找到可用的 host C++ 工具链，无法编译 RTP host 单测。' -ForegroundColor Yellow
    Write-Host '任装一种即可（详见 CONTRIBUTING.md）：'
    Write-Host '  1. Visual Studio Build Tools 2022（工作负载选「使用 C++ 的桌面开发」），自带 cmake 与 ninja'
    Write-Host '  2. LLVM/clang++（https://github.com/llvm/llvm-project/releases）+ ninja'
    Write-Host '  3. MinGW-w64 / TDM-GCC：把 g++.exe 所在目录加入 PATH（自带 mingw32-make）'
    Write-Host '  4. WSL：wsl --install 之后在发行版里 apt install cmake build-essential'
    Write-Host '另外需要 cmake 3.22+：可单独安装，或把 Android SDK 的 cmake 目录加入 PATH。'
    Write-Host ''
    Write-Host '本次探测结果：'
    foreach ($line in $script:Probe) { Write-Host "  $line" }
    exit 1
}

# ---- 6. 依次尝试，直到构建成功 ----------------------------------------------
Write-Host '[run_host_tests] 工具链探测结果：'
foreach ($line in $script:Probe) { Write-Host "  $line" }
Write-Host ''

if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }

$attempt = 0
foreach ($candidate in $candidates) {
    $attempt++
    Write-Step ("工具链 {0}/{1}：{2}" -f $attempt, $candidates.Count, $candidate.Name)
    try {
        if ($candidate.VcVars) {
            Import-VcVarsEnvironment -VcVarsPath $candidate.VcVars
            Write-Step ("已导入 vcvars 环境：{0}" -f $candidate.VcVars)
        }
        if ($candidate.Ninja) { Add-DirToPath -Directory (Split-Path -Parent $candidate.Ninja) }
        if ($candidate.Make) { Add-DirToPath -Directory (Split-Path -Parent $candidate.Make) }

        if ($Clean -or $attempt -gt 1) {
            if (Test-Path -LiteralPath $BuildDir) {
                try {
                    Remove-Item -LiteralPath $BuildDir -Recurse -Force -ErrorAction Stop
                }
                catch {
                    # 删不掉就把 CMake 缓存清掉：换编译器复用旧缓存会被 CMake 直接拒绝。
                    Write-Step ("清理构建目录失败（继续）：{0}" -f $_.Exception.Message)
                    foreach ($stale in @('CMakeCache.txt', 'CMakeFiles')) {
                        $stalePath = Join-Path $BuildDir $stale
                        if (Test-Path -LiteralPath $stalePath) {
                            Remove-Item -LiteralPath $stalePath -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        }

        if ($candidate.Kind -eq 'wsl') {
            $wslSource = ConvertTo-WslPath -WindowsPath $SourceDir
            $wslBuild = ConvertTo-WslPath -WindowsPath $BuildDir
            $testArgument = ''
            if ($Test) { $testArgument = " -tc='" + ($Test -join ',') + "'" }
            $wslCommand = "set -e; cd '$wslSource'; " +
                "cmake -S . -B '$wslBuild' -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=Debug; " +
                "cmake --build '$wslBuild' --parallel; cd '$wslBuild'; ./$ExeName$testArgument"
            Write-Step ("wsl bash -lc `"{0}`"" -f $wslCommand)
            & wsl bash -lc $wslCommand 2>&1 | Tee-Object -FilePath (Join-Path $LogDir 'wsl.log')
            $exitCode = $LASTEXITCODE
            Write-Step ("测试退出码：{0}" -f $exitCode)
            exit $exitCode
        }

        $configureArgs = @('-S', $SourceDir, '-B', $BuildDir, '-G', $candidate.Generator)
        if ($candidate.Compiler) {
            # 必须给正斜杠：CMake（3.22.1 实测）会把 -D 的值原样写进 CMakeCXXCompiler.cmake，
            # 反斜杠会变成非法转义（Invalid character escape '\T'）。
            $configureArgs += ('-DCMAKE_CXX_COMPILER=' + ($candidate.Compiler -replace '\\', '/'))
        }
        $configureArgs += '-DCMAKE_BUILD_TYPE=Debug'
        Write-Step ('cmake ' + ($configureArgs -join ' '))
        & $candidate.Cmake @configureArgs 2>&1 |
            Tee-Object -FilePath (Join-Path $LogDir ("configure_{0}.log" -f $attempt))
        if ($LASTEXITCODE -ne 0) {
            Write-Step ("配置失败（exit {0}），换下一个工具链" -f $LASTEXITCODE)
            continue
        }

        & $candidate.Cmake '--build' $BuildDir '--parallel' 2>&1 |
            Tee-Object -FilePath (Join-Path $LogDir ("build_{0}.log" -f $attempt))
        if ($LASTEXITCODE -ne 0) {
            Write-Step ("构建失败（exit {0}），换下一个工具链" -f $LASTEXITCODE)
            continue
        }

        $exe = Get-ChildItem -LiteralPath $BuildDir -Recurse -File -Filter ($ExeName + '.exe') -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $exe) {
            $exe = Get-ChildItem -LiteralPath $BuildDir -Recurse -File -Filter $ExeName -ErrorAction SilentlyContinue |
                Select-Object -First 1
        }
        if (-not $exe) {
            Write-Step '构建成功但找不到测试可执行文件，换下一个工具链'
            continue
        }

        $testArgs = @()
        $displayArgs = ''
        if ($Test) {
            $testArgs += ('--test-case=' + ($Test -join ','))
            $displayArgs = ' ' + ($testArgs -join ' ')
        }
        Write-Step ("运行 {0}{1}" -f $exe.FullName, $displayArgs)
        $testLog = Join-Path $LogDir ("tests_{0}.log" -f $attempt)
        & $exe.FullName @testArgs 2>&1 | Tee-Object -FilePath $testLog
        $exitCode = $LASTEXITCODE
        Write-Step ("测试退出码：{0}" -f $exitCode)

        # -Test 一个用例都没匹配到时 doctest 也返回 0：拦一下，别把空跑当成通过。
        if ($exitCode -eq 0 -and $Test) {
            $summary = Select-String -LiteralPath $testLog -Pattern 'test cases:\s*(\d+)' -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($summary -and $summary.Matches[0].Groups[1].Value -eq '0') {
                Write-Host ''
                Write-Host ("-Test 没有匹配到任何用例：{0}（不要把它当成通过）" -f ($Test -join ',')) -ForegroundColor Yellow
                exit 1
            }
        }
        exit $exitCode
    }
    catch {
        Write-Step ("尝试失败：{0}" -f $_.Exception.Message)
        continue
    }
}

Write-Host ''
Write-Host ("所有 {0} 个候选工具链都没能构建成功（完整输出见 {1}）" -f $candidates.Count, $LogDir) -ForegroundColor Yellow
Write-Host '本次探测结果：'
foreach ($line in $script:Probe) { Write-Host "  $line" }
exit 1
