param(
    [string]$ResultsRoot = 'build/tls-008/device',
    [string]$Report = 'build/tls-008/gate.json',
    [string]$ProbeLibDir = 'build/tls-008',
    [string]$Arm64Serial = '',
    [string]$X86Serial = '',
    [string]$Python = 'python',
    [string]$Adb = 'adb',
    [switch]$Run
)
$ErrorActionPreference = 'Stop'
$arguments = @((Join-Path $PSScriptRoot 'summarize_probe.py'), '--results-root', $ResultsRoot,
    '--report', $Report, '--probe-lib-dir', $ProbeLibDir, '--adb', $Adb)
if ($Run) {
    $arguments += @('--run', '--arm64-serial', $Arm64Serial, '--x86-serial', $X86Serial)
}
& $Python @arguments
exit $LASTEXITCODE
