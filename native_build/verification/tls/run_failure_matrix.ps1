param(
    [string]$Python = 'python',
    [string]$Go = 'go',
    [string]$Adb = 'adb',
    [string]$Arm64Serial = '',
    [string]$ResultsRoot = '',
    [switch]$SkipDevice,
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
$matrixArguments = @((Join-Path $PSScriptRoot 'failure_matrix_runner.py'), '--go', $Go, '--adb', $Adb)
if ($Arm64Serial) { $matrixArguments += @('--arm64-serial', $Arm64Serial) }
if ($ResultsRoot) { $matrixArguments += @('--results-root', $ResultsRoot) }
if ($SkipDevice) { $matrixArguments += '--skip-device' }
if ($Offline) { $matrixArguments += '--offline' }
& $Python @matrixArguments
exit $LASTEXITCODE
