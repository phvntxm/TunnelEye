# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for TunnelEye collectors: module envelope, per-source error
# capture, native command runner and JSON serialization (see docs/schema).
# Keep this file ASCII-only: PowerShell 5.1 reads BOM-less scripts as ANSI.

Set-StrictMode -Version 2.0

Add-Type -AssemblyName System.Web.Extensions

$script:ToolName = 'TunnelEye'
$script:ToolVersion = '0.1.0'
$script:ModuleSchema = 'tunneleye.module/1'
$script:SnapshotSchema = 'tunneleye.snapshot/1'
$script:MaxDepth = 32
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Get-TunnelEyeInfo {
    [ordered]@{
        name           = $script:ToolName
        version        = $script:ToolVersion
        moduleSchema   = $script:ModuleSchema
        snapshotSchema = $script:SnapshotSchema
    }
}

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Format-Timestamp {
    param([Parameter(Mandatory)][datetime]$Value)
    $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

# --- Serialization ----------------------------------------------------------

function ConvertTo-CollectorData {
    # Normalizes any object into plain JSON-ready types: Dictionary[string,object],
    # object[], string, bool, numbers, null. Enums become strings, dates become
    # ISO 8601 UTC, arrays stay arrays even with 0 or 1 element.
    param(
        [AllowNull()] $InputObject,
        [int] $Depth = 0
    )

    if ($null -eq $InputObject) { return $null }
    # Unwrap PSObject so JavaScriptSerializer never sees it; PSCustomObject keeps
    # its wrapper because the note properties live there.
    $base = $InputObject.PSObject.BaseObject
    if ($base -isnot [System.Management.Automation.PSCustomObject]) { $InputObject = $base }
    if ($Depth -gt $script:MaxDepth) { return [string]$InputObject }

    if ($InputObject -is [string]) { return $InputObject }
    if ($InputObject -is [char]) { return [string]$InputObject }
    if ($InputObject -is [enum]) { return $InputObject.ToString() }
    if ($InputObject -is [bool]) { return $InputObject }
    if ($InputObject -is [double] -or $InputObject -is [single]) {
        $d = [double]$InputObject
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return $null }
        return $d
    }
    if ($InputObject -is [byte] -or $InputObject -is [sbyte] -or
        $InputObject -is [int16] -or $InputObject -is [uint16] -or
        $InputObject -is [int32] -or $InputObject -is [uint32] -or
        $InputObject -is [int64] -or $InputObject -is [uint64] -or
        $InputObject -is [decimal]) {
        return $InputObject
    }
    if ($InputObject -is [datetime]) { return (Format-Timestamp $InputObject) }
    if ($InputObject -is [datetimeoffset]) { return (Format-Timestamp $InputObject.UtcDateTime) }
    if ($InputObject -is [timespan]) { return [double]$InputObject.TotalMilliseconds }
    if ($InputObject -is [guid] -or $InputObject -is [version] -or
        $InputObject -is [uri] -or $InputObject -is [System.Net.IPAddress]) {
        return $InputObject.ToString()
    }
    if ($InputObject -is [System.Security.SecureString]) { return $null }
    if ($InputObject -is [byte[]]) {
        return [BitConverter]::ToString($InputObject).Replace('-', '').ToLowerInvariant()
    }

    $next = $Depth + 1

    if ($InputObject.GetType().FullName -eq 'Microsoft.Management.Infrastructure.CimInstance') {
        $dict = [System.Collections.Generic.Dictionary[string,object]]::new()
        foreach ($p in $InputObject.CimInstanceProperties) {
            $dict[$p.Name] = ConvertTo-CollectorData -InputObject $p.Value -Depth $next
        }
        return $dict
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $dict = [System.Collections.Generic.Dictionary[string,object]]::new()
        foreach ($key in $InputObject.Keys) {
            $dict[[string]$key] = ConvertTo-CollectorData -InputObject $InputObject[$key] -Depth $next
        }
        return $dict
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) {
            $list.Add((ConvertTo-CollectorData -InputObject $item -Depth $next))
        }
        return , $list.ToArray()
    }
    if ($InputObject -is [ValueType]) { return $InputObject.ToString() }

    $dict = [System.Collections.Generic.Dictionary[string,object]]::new()
    foreach ($p in $InputObject.PSObject.Properties) {
        if ($p.MemberType -notin 'NoteProperty', 'Property', 'AliasProperty') { continue }
        try { $value = $p.Value } catch { $value = $null }
        $dict[$p.Name] = ConvertTo-CollectorData -InputObject $value -Depth $next
    }
    return $dict
}

function New-JsonSerializer {
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = [int]::MaxValue
    $serializer.RecursionLimit = 256
    $serializer
}

function ConvertTo-CollectorJson {
    param(
        [AllowNull()] $InputObject,
        # Skip normalization for data that is already plain (e.g. deserialized JSON).
        [switch] $Normalized
    )
    $plain = if ($Normalized) { $InputObject } else { ConvertTo-CollectorData -InputObject $InputObject }
    (New-JsonSerializer).Serialize($plain)
}

function ConvertFrom-CollectorJson {
    # Returns Dictionary[string,object] / object[] / primitives, without the
    # array unwrapping and PSCustomObject conversion of ConvertFrom-Json.
    param([Parameter(Mandatory)][string] $Json)
    (New-JsonSerializer).DeserializeObject($Json)
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $Json
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [IO.File]::WriteAllText($Path, $Json, $script:Utf8NoBom)
}

# --- Errors -----------------------------------------------------------------

function Get-ErrorKind {
    # Maps an ErrorRecord or Exception to: AccessDenied, NotSupported, NotFound,
    # Timeout or Exception.
    param([Parameter(Mandatory)] $ErrorObject)

    $exception = $ErrorObject
    $category = $null
    if ($ErrorObject -is [System.Management.Automation.ErrorRecord]) {
        $exception = $ErrorObject.Exception
        $category = [string]$ErrorObject.CategoryInfo.Category
    }

    for ($e = $exception; $null -ne $e; $e = $e.InnerException) {
        if ($e -is [UnauthorizedAccessException] -or $e -is [System.Security.SecurityException]) { return 'AccessDenied' }
        if ($e -is [TimeoutException]) { return 'Timeout' }
        if ($e -is [System.Management.Automation.CommandNotFoundException] -or
            $e -is [PlatformNotSupportedException] -or
            $e -is [NotSupportedException]) { return 'NotSupported' }
        if ($e -is [System.Management.Automation.ItemNotFoundException] -or
            $e -is [IO.FileNotFoundException] -or
            $e -is [IO.DirectoryNotFoundException]) { return 'NotFound' }
        if ($e -is [System.ComponentModel.Win32Exception]) {
            switch ($e.NativeErrorCode) {
                5 { return 'AccessDenied' }
                2 { return 'NotFound' }
                3 { return 'NotFound' }
                1460 { return 'Timeout' }
            }
        }
        if ($e.GetType().FullName -eq 'Microsoft.Management.Infrastructure.CimException') {
            switch ([string]$e.NativeErrorCode) {
                'AccessDenied' { return 'AccessDenied' }
                'NotSupported' { return 'NotSupported' }
                'InvalidClass' { return 'NotSupported' }
                'InvalidNamespace' { return 'NotSupported' }
                'NotFound' { return 'NotFound' }
            }
        }
    }

    switch ($category) {
        'PermissionDenied' { return 'AccessDenied' }
        'SecurityError' { return 'AccessDenied' }
        'ObjectNotFound' { return 'NotFound' }
        'NotImplemented' { return 'NotSupported' }
        'OperationTimeout' { return 'Timeout' }
    }
    'Exception'
}

function Add-CollectorError {
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)][string] $Source,
        [Parameter(Mandatory)][ValidateSet('AccessDenied', 'NotSupported', 'NotFound', 'Timeout', 'Exception')][string] $Kind,
        [AllowEmptyString()][string] $Message = '',
        [switch] $Fatal
    )
    $Context.Errors.Add([ordered]@{
            source  = $Source
            kind    = $Kind
            message = $Message
            fatal   = [bool]$Fatal
        })
}

# --- Collector lifecycle ----------------------------------------------------

function New-CollectorContext {
    param(
        [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9-]*$')][string] $Module,
        [Parameter(Mandatory)][string] $Version
    )
    [pscustomobject]@{
        Module    = $Module
        Version   = $Version
        Elevated  = [bool](Test-Elevated)
        StartedAt = [datetime]::UtcNow
        Stopwatch = [Diagnostics.Stopwatch]::StartNew()
        Errors    = [System.Collections.Generic.List[object]]::new()
    }
}

function Invoke-Source {
    # Runs one data source. Terminating and non-terminating errors are recorded
    # in the context and never escape. Returns $null if the source failed.
    # -AsList: on success always returns an array (possibly empty or 1 item).
    # Non-terminating errors with partial output keep the output.
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)][string] $Source,
        [Parameter(Mandatory)][scriptblock] $ScriptBlock,
        [switch] $AsList,
        [switch] $RequiresAdmin
    )

    if ($RequiresAdmin -and -not $Context.Elevated) {
        Add-CollectorError -Context $Context -Source $Source -Kind AccessDenied -Message 'Requires administrator rights; source skipped.'
        return $null
    }

    $items = [System.Collections.Generic.List[object]]::new()
    $failed = $false
    try {
        # 2>&1 catches non-terminating errors regardless of the caller's
        # $ErrorActionPreference (which this module scope cannot change).
        foreach ($item in (& $ScriptBlock 2>&1)) {
            if ($item -is [System.Management.Automation.ErrorRecord]) {
                Add-CollectorError -Context $Context -Source $Source -Kind (Get-ErrorKind $item) -Message $item.Exception.Message
            }
            else {
                $items.Add($item)
            }
        }
    }
    catch {
        Add-CollectorError -Context $Context -Source $Source -Kind (Get-ErrorKind $_) -Message $_.Exception.Message
        $failed = $true
    }

    if ($failed) { return $null }
    if ($AsList) { return , $items.ToArray() }
    if ($items.Count -eq 0) { return $null }
    if ($items.Count -eq 1) { return $items[0] }
    return , $items.ToArray()
}

function Get-OemEncoding {
    # Console tools (netsh, pnputil) write in the system OEM code page.
    try {
        $cp = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage' -Name OEMCP -ErrorAction Stop).OEMCP
        return [Text.Encoding]::GetEncoding([int]$cp)
    }
    catch {
        return [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
    }
}

function ConvertFrom-NativeBytes {
    # Console tools write in the console code page they inherit: OEM (866 on
    # Russian Windows) in a fresh console, UTF-8 if the parent ran chcp 65001.
    # Some tools write UTF-16LE. Detect instead of guessing: BOM, then UTF-16
    # by NUL bytes, then strict UTF-8, then OEM.
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]] $Bytes)

    if ($Bytes.Length -eq 0) { return '' }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
        return [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2)
    }
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        return [Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3)
    }
    if ($Bytes.Length -ge 4 -and $Bytes[0] -ne 0 -and $Bytes[1] -eq 0 -and $Bytes[3] -eq 0) {
        return [Text.Encoding]::Unicode.GetString($Bytes)
    }
    try {
        return (New-Object System.Text.UTF8Encoding($false, $true)).GetString($Bytes)
    }
    catch {
        return (Get-OemEncoding).GetString($Bytes)
    }
}

function ConvertTo-CommandLineArgument {
    param([AllowEmptyString()][string] $Value)
    if ($Value -eq '') { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-NativeCommand {
    # Runs a console tool with a timeout. Returns @{ exitCode; stdout; stderr }
    # or $null if it could not start or timed out. A non-success exit code is
    # recorded as an error but the output is still returned.
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)][string] $Source,
        [Parameter(Mandatory)][string] $FilePath,
        [string[]] $ArgumentList = @(),
        [int] $TimeoutSec = 60,
        [int[]] $SuccessExitCodes = @(0),
        [switch] $RequiresAdmin
    )

    if ($RequiresAdmin -and -not $Context.Elevated) {
        Add-CollectorError -Context $Context -Source $Source -Kind AccessDenied -Message 'Requires administrator rights; source skipped.'
        return $null
    }

    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = (@($ArgumentList | ForEach-Object { ConvertTo-CommandLineArgument $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    try {
        [void]$process.Start()
    }
    catch {
        Add-CollectorError -Context $Context -Source $Source -Kind (Get-ErrorKind $_) -Message $_.Exception.Message
        return $null
    }

    try {
        $stdout = New-Object IO.MemoryStream
        $stderr = New-Object IO.MemoryStream
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
        if (-not $process.WaitForExit($TimeoutSec * 1000)) {
            try { $process.Kill() } catch { }
            Add-CollectorError -Context $Context -Source $Source -Kind Timeout -Message "Timed out after $TimeoutSec s."
            return $null
        }
        $process.WaitForExit()
        [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask), 5000)
        $result = [pscustomobject]@{
            exitCode = $process.ExitCode
            stdout   = ConvertFrom-NativeBytes -Bytes $stdout.ToArray()
            stderr   = ConvertFrom-NativeBytes -Bytes $stderr.ToArray()
        }
    }
    finally {
        $process.Dispose()
    }

    if ($SuccessExitCodes -notcontains $result.exitCode) {
        $detail = ($result.stderr, $result.stdout | Where-Object { $_ -and $_.Trim() } | Select-Object -First 1)
        if ($detail) { $detail = $detail.Trim() }
        if ($detail -and $detail.Length -gt 500) { $detail = $detail.Substring(0, 500) }
        Add-CollectorError -Context $Context -Source $Source -Kind Exception -Message ("Exit code {0}. {1}" -f $result.exitCode, $detail).Trim()
    }
    $result
}

function Complete-Collector {
    # Builds the module envelope. Status: skipped (-Skipped), failed (no data),
    # partial (data with errors), ok.
    param(
        [Parameter(Mandatory)] $Context,
        [AllowNull()] $Data,
        [switch] $Skipped,
        [string] $SkipReason
    )

    if ($Skipped) {
        if ($SkipReason) {
            Add-CollectorError -Context $Context -Source 'collector' -Kind NotSupported -Message $SkipReason
        }
        $status = 'skipped'
        $Data = $null
    }
    elseif ($null -eq $Data) { $status = 'failed' }
    elseif ($Context.Errors.Count -gt 0) { $status = 'partial' }
    else { $status = 'ok' }

    $Context.Stopwatch.Stop()
    [ordered]@{
        schema     = $script:ModuleSchema
        module     = $Context.Module
        version    = $Context.Version
        status     = $status
        elevated   = $Context.Elevated
        startedAt  = Format-Timestamp $Context.StartedAt
        durationMs = [int64]$Context.Stopwatch.ElapsedMilliseconds
        errors     = $Context.Errors.ToArray()
        data       = $Data
    }
}

function Write-CollectorResult {
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Envelope,
        [string] $OutFile
    )
    process {
        $json = ConvertTo-CollectorJson -InputObject $Envelope
        if ($OutFile) { Write-JsonFile -Path $OutFile -Json $json }
        else { $json }
    }
}

function Invoke-Collector {
    # Entry point for a collector script. The script block receives the context
    # and returns the module data (an ordered hashtable), or $null on failure.
    # To mark the module as not applicable, return (New-SkipResult 'reason').
    param(
        [Parameter(Mandatory)][string] $Module,
        [Parameter(Mandatory)][string] $Version,
        [Parameter(Mandatory)][scriptblock] $ScriptBlock,
        [string] $OutFile
    )

    $context = New-CollectorContext -Module $Module -Version $Version
    $data = $null
    $skip = $null
    try {
        $data = & $ScriptBlock $context
        if ($null -ne $data -and $data.PSObject.Properties['IsTunnelEyeSkip']) {
            $skip = $data.Reason
            $data = $null
        }
        elseif ($null -ne $data -and $data -isnot [System.Collections.IDictionary]) {
            # Usually a stray pipeline output inside the collector.
            Add-CollectorError -Context $context -Source 'collector' -Kind Exception -Fatal `
                -Message ("Collector returned {0} instead of a dictionary." -f $data.GetType().FullName)
            $data = $null
        }
    }
    catch {
        Add-CollectorError -Context $context -Source 'collector' -Kind (Get-ErrorKind $_) -Message $_.Exception.Message -Fatal
        $data = $null
    }

    if ($null -ne $skip) {
        $envelope = Complete-Collector -Context $context -Skipped -SkipReason $skip
    }
    else {
        $envelope = Complete-Collector -Context $context -Data $data
    }
    Write-CollectorResult -Envelope $envelope -OutFile $OutFile
}

function New-SkipResult {
    param([Parameter(Mandatory)][string] $Reason)
    [pscustomobject]@{ IsTunnelEyeSkip = $true; Reason = $Reason }
}

Export-ModuleMember -Function @(
    'Get-TunnelEyeInfo', 'Test-Elevated', 'Format-Timestamp',
    'ConvertTo-CollectorData', 'ConvertTo-CollectorJson', 'ConvertFrom-CollectorJson', 'Write-JsonFile',
    'Get-ErrorKind', 'Add-CollectorError',
    'New-CollectorContext', 'Invoke-Source', 'Invoke-NativeCommand', 'ConvertFrom-NativeBytes',
    'Complete-Collector', 'Write-CollectorResult', 'Invoke-Collector', 'New-SkipResult'
)
