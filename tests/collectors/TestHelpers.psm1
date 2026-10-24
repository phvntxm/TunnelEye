# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for collector tests (Pester 3.4, built into Windows).

Set-StrictMode -Version 2.0

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
Import-Module (Join-Path $script:RepoRoot 'collectors\TunnelEye.Common.psm1') -Force

function Get-RepoRoot { $script:RepoRoot }

function Invoke-CollectorScript {
    # Runs a collector the same way the orchestrator does (separate process)
    # and returns the parsed envelope (Dictionary[string,object]).
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $OutFile
    )
    $ps = Join-Path $PSHOME 'powershell.exe'
    & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Path -OutFile $OutFile | Out-Null
    ConvertFrom-CollectorJson -Json ([IO.File]::ReadAllText($OutFile, [Text.Encoding]::UTF8))
}

function Get-EnvelopeProblems {
    # Returns a list of schema violations of a module envelope (empty = valid).
    param([Parameter(Mandatory)] $Envelope, [string] $Module)
    $problems = New-Object System.Collections.Generic.List[string]
    $expected = 'schema', 'module', 'version', 'status', 'elevated', 'startedAt', 'durationMs', 'errors', 'data'
    foreach ($key in $expected) {
        if (-not $Envelope.ContainsKey($key)) { $problems.Add("missing '$key'") }
    }
    foreach ($key in $Envelope.Keys) {
        if ($expected -notcontains $key) { $problems.Add("unexpected '$key'") }
    }
    if ($problems.Count) { return , $problems.ToArray() }

    if ($Envelope['schema'] -ne 'tunneleye.module/1') { $problems.Add('bad schema') }
    if ($Module -and $Envelope['module'] -ne $Module) { $problems.Add('module name mismatch') }
    if ('ok', 'partial', 'failed', 'skipped' -notcontains $Envelope['status']) { $problems.Add('bad status') }
    if ($Envelope['elevated'] -isnot [bool]) { $problems.Add('elevated is not bool') }
    if ($Envelope['startedAt'] -notmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$') { $problems.Add('bad startedAt') }
    if ($Envelope['durationMs'] -isnot [int] -and $Envelope['durationMs'] -isnot [long]) { $problems.Add('durationMs is not integer') }
    if ($Envelope['errors'] -isnot [object[]]) { $problems.Add('errors is not array') }
    else {
        foreach ($e in $Envelope['errors']) {
            foreach ($key in 'source', 'kind', 'message', 'fatal') {
                if (-not $e.ContainsKey($key)) { $problems.Add("error without '$key'") }
            }
            if ('AccessDenied', 'NotSupported', 'NotFound', 'Timeout', 'Exception' -notcontains $e['kind']) {
                $problems.Add("bad error kind '$($e['kind'])'")
            }
        }
    }
    switch ($Envelope['status']) {
        'ok' { if ($Envelope['errors'].Count) { $problems.Add('ok with errors') }; if ($null -eq $Envelope['data']) { $problems.Add('ok without data') } }
        'partial' { if (-not $Envelope['errors'].Count) { $problems.Add('partial without errors') }; if ($null -eq $Envelope['data']) { $problems.Add('partial without data') } }
        'failed' { if ($null -ne $Envelope['data']) { $problems.Add('failed with data') } }
        'skipped' { if ($null -ne $Envelope['data']) { $problems.Add('skipped with data') } }
    }
    , $problems.ToArray()
}

function Find-KeyPaths {
    # Walks the data tree without recursion (an explicit stack: recursive
    # calls returning arrays took seconds on the ~1 MB firewall data) and
    # returns the paths of dictionary keys for which $Test returns true.
    param([AllowNull()] $Node, [string] $Path, [Parameter(Mandatory)][scriptblock] $Test)
    $bad = [System.Collections.Generic.List[string]]::new()
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push(@($Node, $Path))
    while ($stack.Count) {
        $item = $stack.Pop()
        $n = $item[0]
        $p = $item[1]
        if ($n -is [System.Collections.IDictionary]) {
            foreach ($key in $n.Keys) {
                if (& $Test $key) { $bad.Add("$p.$key") }
                $child = $n[$key]
                if ($child -is [System.Collections.IDictionary] -or $child -is [object[]]) { $stack.Push(@($child, "$p.$key")) }
            }
        }
        elseif ($n -is [object[]]) {
            for ($i = 0; $i -lt $n.Count; $i++) {
                $child = $n[$i]
                if ($child -is [System.Collections.IDictionary] -or $child -is [object[]]) { $stack.Push(@($child, "$p[$i]")) }
            }
        }
    }
    $bad.Sort()
    , $bad.ToArray()
}

function Get-NonCamelCaseKeys {
    # Returns key paths in data that are not camelCase (data maps with
    # data-derived keys are not allowed; use arrays of objects instead).
    param([AllowNull()] $Node, [string] $Path = 'data')
    Find-KeyPaths -Node $Node -Path $Path -Test { param($k) $k -cnotmatch '^[a-z][a-zA-Z0-9]*$' }
}

function Get-SensitiveKeys {
    # Returns key paths whose names suggest secrets (must never be collected).
    param([AllowNull()] $Node, [string] $Path = 'data')
    Find-KeyPaths -Node $Node -Path $Path -Test { param($k) $k -match 'password|passphrase|keyMaterial|secret|psk|credential|token' }
}

Export-ModuleMember -Function Get-RepoRoot, Invoke-CollectorScript, Get-EnvelopeProblems, Get-NonCamelCaseKeys, Get-SensitiveKeys
