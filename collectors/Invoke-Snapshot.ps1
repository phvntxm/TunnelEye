# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Stage 1 orchestrator: runs each collector in its own powershell.exe with a
# timeout and assembles snapshot.json. A crashed, hung or misbehaving collector
# becomes a 'failed' envelope; the other collectors are not affected.

[CmdletBinding()]
param(
    [string] $OutputDirectory,
    [string[]] $Modules = @(
        'system', 'adapters', 'routing', 'dns-proxy', 'vpn', 'firewall', 'services',
        'connections', 'tcp-stack', 'wifi', 'events', 'hardware', 'connectivity'
    ),
    [string] $CollectorPath = $PSScriptRoot,
    [ValidateRange(1, 3600)][int] $TimeoutSec = 120,
    # Explicit consent to external connection tests (D-002), per run only:
    # passed to the 'connectivity' module and recorded in snapshot.json.
    [switch] $AllowExternal
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

$validStatuses = 'ok', 'partial', 'failed', 'skipped'

function New-FailedEnvelope {
    param([string] $Module, [string] $Kind, [string] $Message, [datetime] $StartedAt, [int64] $DurationMs, [bool] $Elevated)
    $dict = [System.Collections.Generic.Dictionary[string,object]]::new()
    $dict['schema'] = (Get-TunnelEyeInfo).moduleSchema
    $dict['module'] = $Module
    $dict['version'] = $null
    $dict['status'] = 'failed'
    $dict['elevated'] = $Elevated
    $dict['startedAt'] = Format-Timestamp $StartedAt
    $dict['durationMs'] = $DurationMs
    $error0 = [System.Collections.Generic.Dictionary[string,object]]::new()
    $error0['source'] = 'orchestrator'
    $error0['kind'] = $Kind
    $error0['message'] = $Message
    $error0['fatal'] = $true
    $dict['errors'] = [object[]]@($error0)
    $dict['data'] = $null
    $dict
}

function Test-Envelope {
    # Returns $null if the envelope is valid, otherwise a reason.
    param($Envelope, [string] $Module)
    if ($Envelope -isnot [System.Collections.Generic.Dictionary[string, object]]) { return 'Output is not a JSON object.' }
    foreach ($key in 'schema', 'module', 'version', 'status', 'elevated', 'startedAt', 'durationMs', 'errors', 'data') {
        if (-not $Envelope.ContainsKey($key)) { return "Missing field '$key'." }
    }
    if ($Envelope['module'] -ne $Module) { return "Module name '$($Envelope['module'])' does not match '$Module'." }
    if ($validStatuses -notcontains $Envelope['status']) { return "Unknown status '$($Envelope['status'])'." }
    if ($Envelope['errors'] -isnot [object[]]) { return "Field 'errors' is not an array." }
    $null
}

function Invoke-ModuleProcess {
    param([string] $Module, [string] $Script, [string] $OutFile, [int] $TimeoutSec, [bool] $Elevated, [string] $ExtraArguments = '')

    $startedAt = [datetime]::UtcNow
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $fail = { param($kind, $message) New-FailedEnvelope -Module $Module -Kind $kind -Message $message -StartedAt $startedAt -DurationMs $watch.ElapsedMilliseconds -Elevated $Elevated }

    if (-not (Test-Path -LiteralPath $Script)) {
        return (& $fail 'NotFound' "Collector script not found: $(Split-Path -Leaf $Script)")
    }

    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $PSHOME 'powershell.exe'
    # Bypass applies to this child process only; the machine policy is untouched.
    $psi.Arguments = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -OutFile "{1}" {2}' -f $Script, $OutFile, $ExtraArguments).TrimEnd()
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSec * 1000)) {
            # Kill the whole tree: collectors may have started console tools.
            & taskkill.exe /PID $process.Id /T /F 2>&1 | Out-Null
            return (& $fail 'Timeout' "Collector did not finish in $TimeoutSec s and was terminated.")
        }
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        $stderr = $stderrTask.Result
        [void]$stdoutTask.Result
    }
    catch {
        return (& $fail (Get-ErrorKind $_) $_.Exception.Message)
    }
    finally {
        $process.Dispose()
    }

    if (-not (Test-Path -LiteralPath $OutFile)) {
        $detail = if ($stderr) { $stderr.Trim() } else { '' }
        if ($detail.Length -gt 2000) { $detail = $detail.Substring(0, 2000) }
        return (& $fail 'Exception' ("Collector produced no output (exit code {0}). {1}" -f $exitCode, $detail).Trim())
    }

    try {
        $envelope = ConvertFrom-CollectorJson -Json ([IO.File]::ReadAllText($OutFile, [Text.Encoding]::UTF8))
    }
    catch {
        return (& $fail 'Exception' "Collector output is not valid JSON: $($_.Exception.Message)")
    }
    $problem = Test-Envelope -Envelope $envelope -Module $Module
    if ($problem) { return (& $fail 'Exception' "Invalid collector output: $problem") }
    $envelope
}

function Get-OsBuild {
    try {
        $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $ubr = if ($cv.PSObject.Properties['UBR']) { ".$($cv.UBR)" } else { '' }
        "$($cv.CurrentBuild)$ubr"
    }
    catch { $null }
}

# --- Main -------------------------------------------------------------------

$createdAt = [datetime]::UtcNow
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path (Get-Location) ('output\snapshot-' + $createdAt.ToLocalTime().ToString('yyyyMMdd-HHmmss'))
}
$moduleDir = Join-Path $OutputDirectory 'modules'
New-Item -ItemType Directory -Path $moduleDir -Force | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).ProviderPath
$moduleDir = Join-Path $OutputDirectory 'modules'

$elevated = [bool](Test-Elevated)
$info = Get-TunnelEyeInfo
$totalWatch = [Diagnostics.Stopwatch]::StartNew()
# Generic Dictionary keeps insertion order here (no removals) and, unlike
# OrderedDictionary, never holds PSObject wrappers the serializer cannot handle.
$results = [System.Collections.Generic.Dictionary[string,object]]::new()
$counts = [ordered]@{ ok = 0; partial = 0; failed = 0; skipped = 0 }

for ($i = 0; $i -lt $Modules.Count; $i++) {
    $module = $Modules[$i]
    Write-Progress -Activity 'TunnelEye snapshot' -Status $module -PercentComplete ([int](100 * $i / $Modules.Count))
    $extra = ''
    if ($module -eq 'connectivity' -and $AllowExternal) { $extra = '-AllowExternal' }
    $envelope = Invoke-ModuleProcess -Module $module `
        -Script (Join-Path $CollectorPath "$module.ps1") `
        -OutFile (Join-Path $moduleDir "$module.json") `
        -TimeoutSec $TimeoutSec -Elevated $elevated -ExtraArguments $extra
    $results[$module] = $envelope
    $counts[[string]$envelope['status']]++
}
Write-Progress -Activity 'TunnelEye snapshot' -Completed
$totalWatch.Stop()

$snapshot = [ordered]@{
    schema     = $info.snapshotSchema
    snapshotId = [guid]::NewGuid().ToString()
    createdAt  = Format-Timestamp $createdAt
    tool       = [ordered]@{ name = $info.name; version = $info.version }
    host       = [ordered]@{
        osBuild   = Get-OsBuild
        psVersion = $PSVersionTable.PSVersion.ToString()
        culture   = (Get-Culture).Name
        uiCulture = (Get-UICulture).Name
        elevated  = $elevated
    }
    externalAllowed = [bool]$AllowExternal
    summary    = [ordered]@{
        ok         = $counts.ok
        partial    = $counts.partial
        failed     = $counts.failed
        skipped    = $counts.skipped
        durationMs = [int64]$totalWatch.ElapsedMilliseconds
    }
}

# Module envelopes are already plain deserialized JSON: normalize only the
# header, then attach them as is (avoids re-walking large module data).
$plain = ConvertTo-CollectorData -InputObject $snapshot
$plain['modules'] = $results
$snapshotPath = Join-Path $OutputDirectory 'snapshot.json'
Write-JsonFile -Path $snapshotPath -Json (ConvertTo-CollectorJson -InputObject $plain -Normalized)

[pscustomobject]@{
    Path     = $snapshotPath
    Elevated = $elevated
    Ok       = $counts.ok
    Partial  = $counts.partial
    Failed   = $counts.failed
    Skipped  = $counts.skipped
    Seconds  = [math]::Round($totalWatch.Elapsed.TotalSeconds, 1)
}
