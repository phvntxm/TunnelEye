# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Runs the collector tests (meant for an elevated console: the desktop
# shortcut "TunnelEye - Admin" starts it as administrator) and writes the
# NUnit XML result to .local\test-results.xml, which is not committed.

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
Set-Location -LiteralPath $root
New-Item -ItemType Directory -Path (Join-Path $root '.local') -Force | Out-Null

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ("TunnelEye collector tests, elevated = {0}" -f $elevated)

$watch = [Diagnostics.Stopwatch]::StartNew()
$result = Invoke-Pester tests\collectors -OutputFile .local\test-results.xml -OutputFormat NUnitXml -PassThru
$watch.Stop()

Write-Host ''
Write-Host ("Passed {0}, failed {1}, total {2} in {3:N0} s. Result: {4}" -f
    $result.PassedCount, $result.FailedCount, $result.TotalCount, $watch.Elapsed.TotalSeconds, (Join-Path $root '.local\test-results.xml'))
Read-Host 'Press Enter to close' | Out-Null
