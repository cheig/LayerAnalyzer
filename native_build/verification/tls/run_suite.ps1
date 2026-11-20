param(
    [string]$Python = 'python',
    [string]$Tshark = 'tshark',
    [string]$Adb = 'adb',
    [string]$Go = '',
    [string]$Arm64Serial = '',
    [string]$ResultsRoot = '',
    [switch]$SkipDevice,
    [switch]$Incremental,
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
$suiteArguments = @((Join-Path $PSScriptRoot 'suite_runner.py'), '--tshark', $Tshark, '--adb', $Adb)
if ($Arm64Serial) { $suiteArguments += @('--arm64-serial', $Arm64Serial) }
if ($Go) { $suiteArguments += @('--go', $Go) }
if ($ResultsRoot) { $suiteArguments += @('--results-root', $ResultsRoot) }
if ($SkipDevice) { $suiteArguments += '--skip-device' }
if ($Incremental) { $suiteArguments += '--incremental' }
if ($Offline) { $suiteArguments += '--offline' }
& $Python @suiteArguments
exit $LASTEXITCODE
