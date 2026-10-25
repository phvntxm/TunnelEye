# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Orchestrator isolation tests: every fixture misbehaves in its own way, the
# snapshot must still contain all modules with the right status.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force

Describe 'Invoke-Snapshot' {
    $orchestrator = Join-Path (Get-RepoRoot) 'collectors\Invoke-Snapshot.ps1'
    $fixtures = Join-Path $PSScriptRoot 'fixtures'
    $outDir = Join-Path $TestDrive 'snap'
    $modules = 'fixture-ok', 'fixture-partial', 'fixture-skip', 'fixture-throw', 'fixture-stray',
    'fixture-crash', 'fixture-hang', 'fixture-badjson', 'fixture-wrongname', 'fixture-missing'

    $result = & $orchestrator -OutputDirectory $outDir -Modules $modules -CollectorPath $fixtures -TimeoutSec 5
    $snapshot = ConvertFrom-CollectorJson ([IO.File]::ReadAllText($result.Path, [Text.Encoding]::UTF8))
    $m = $snapshot['modules']

    It 'writes snapshot.json and per-module files' {
        Test-Path $result.Path | Should Be $true
        Test-Path (Join-Path $outDir 'modules\fixture-ok.json') | Should Be $true
    }
    It 'has a valid snapshot header' {
        $snapshot['schema'] | Should Be 'tunneleye.snapshot/1'
        $snapshot['snapshotId'] | Should Match '^[0-9a-f-]{36}$'
        $snapshot['createdAt'] | Should Match 'Z$'
        $snapshot['tool']['name'] | Should Be 'TunnelEye'
        $snapshot['host']['elevated'] -is [bool] | Should Be $true
        $snapshot['externalAllowed'] | Should Be $false
    }
    It 'keeps all modules in the requested order' {
        (@($m.Keys) -join ',') | Should Be ($modules -join ',')
    }
    It 'every module has a valid envelope' {
        foreach ($name in $modules) {
            $problems = Get-EnvelopeProblems -Envelope $m[$name] -Module $name
            "${name}: $($problems -join '; ')" | Should Be "${name}: "
        }
    }
    It 'sets status <expected> for <name>' -TestCases @(
        @{ name = 'fixture-ok'; expected = 'ok' }
        @{ name = 'fixture-partial'; expected = 'partial' }
        @{ name = 'fixture-skip'; expected = 'skipped' }
        @{ name = 'fixture-throw'; expected = 'failed' }
        @{ name = 'fixture-stray'; expected = 'failed' }
        @{ name = 'fixture-crash'; expected = 'failed' }
        @{ name = 'fixture-hang'; expected = 'failed' }
        @{ name = 'fixture-badjson'; expected = 'failed' }
        @{ name = 'fixture-wrongname'; expected = 'failed' }
        @{ name = 'fixture-missing'; expected = 'failed' }
    ) {
        param($name, $expected)
        $m[$name]['status'] | Should Be $expected
    }
    It 'classifies orchestrator failures' {
        $m['fixture-hang']['errors'][0]['kind'] | Should Be 'Timeout'
        $m['fixture-missing']['errors'][0]['kind'] | Should Be 'NotFound'
        $m['fixture-crash']['errors'][0]['message'] | Should Match 'fatal crash'
        $m['fixture-wrongname']['errors'][0]['message'] | Should Match 'does not match'
    }
    It 'keeps single-element arrays and enum strings from the collector' {
        $data = $m['fixture-ok']['data']
        , $data['single'] | Should BeOfType [object[]]
        $data['day'] | Should Be 'Friday'
    }
    It 'records the partial module errors per source' {
        $errors = $m['fixture-partial']['errors']
        (@($errors | ForEach-Object { "$($_['source'])=$($_['kind'])" }) -join ',') | Should Be 'broken=Exception,admin=AccessDenied'
        $m['fixture-partial']['data']['good'] | Should Be 1
    }
    It 'counts statuses in the summary' {
        $s = $snapshot['summary']
        "$($s['ok'])/$($s['partial'])/$($s['skipped'])/$($s['failed'])" | Should Be '1/1/1/7'
    }
}

Describe 'Invoke-Snapshot: consent to external tests (D-002)' {
    $orchestrator = Join-Path (Get-RepoRoot) 'collectors\Invoke-Snapshot.ps1'
    $fixtures = Join-Path $PSScriptRoot 'fixtures'

    It 'passes -AllowExternal to connectivity only and records it in the snapshot' {
        $outDir = Join-Path $TestDrive 'external'
        $result = & $orchestrator -OutputDirectory $outDir -Modules 'fixture-ok', 'connectivity' -CollectorPath $fixtures -TimeoutSec 30 -AllowExternal
        $snapshot = ConvertFrom-CollectorJson ([IO.File]::ReadAllText($result.Path, [Text.Encoding]::UTF8))
        $snapshot['externalAllowed'] | Should Be $true
        # fixture-ok has no -AllowExternal parameter: it would fail if it got one.
        $snapshot['modules']['fixture-ok']['status'] | Should Be 'ok'
        $snapshot['modules']['connectivity']['data']['externalAllowed'] | Should Be $true
    }
    It 'does not enable external tests by default' {
        $outDir = Join-Path $TestDrive 'local'
        $result = & $orchestrator -OutputDirectory $outDir -Modules 'connectivity' -CollectorPath $fixtures -TimeoutSec 30
        $snapshot = ConvertFrom-CollectorJson ([IO.File]::ReadAllText($result.Path, [Text.Encoding]::UTF8))
        $snapshot['externalAllowed'] | Should Be $false
        $snapshot['modules']['connectivity']['data']['externalAllowed'] | Should Be $false
    }
}

Describe 'Invoke-Snapshot: started with powershell.exe -File' {
    # In Windows PowerShell 5.1 $PSScriptRoot is empty in parameter defaults
    # under -File; the GUI starts the orchestrator exactly this way (UAC).
    $orchestrator = Join-Path (Get-RepoRoot) 'collectors\Invoke-Snapshot.ps1'
    $outDir = Join-Path $TestDrive 'file-run'
    & (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $orchestrator -OutputDirectory $outDir -Modules 'system' | Out-Null

    It 'finds its collectors and produces an ok envelope' {
        $path = Join-Path $outDir 'snapshot.json'
        Test-Path $path | Should Be $true
        $snapshot = ConvertFrom-CollectorJson ([IO.File]::ReadAllText($path, [Text.Encoding]::UTF8))
        $snapshot['modules']['system']['status'] | Should Be 'ok'
    }
}

Describe 'Invoke-Snapshot: progress.jsonl' {
    $orchestrator = Join-Path (Get-RepoRoot) 'collectors\Invoke-Snapshot.ps1'
    $fixtures = Join-Path $PSScriptRoot 'fixtures'
    $outDir = Join-Path $TestDrive 'progress'
    $null = & $orchestrator -OutputDirectory $outDir -Modules 'fixture-ok', 'fixture-crash' -CollectorPath $fixtures -TimeoutSec 30
    $lines = @([IO.File]::ReadAllLines((Join-Path $outDir 'progress.jsonl'), [Text.Encoding]::UTF8) | Where-Object { $_ })
    $events = @($lines | ForEach-Object { ConvertFrom-CollectorJson $_ })

    It 'writes one JSON line per event in order' {
        ($events | ForEach-Object { $_['event'] + ':' + $_['module'] }) -join ',' |
            Should Be 'start:,moduleStart:fixture-ok,moduleEnd:fixture-ok,moduleStart:fixture-crash,moduleEnd:fixture-crash,end:'
    }
    It 'reports module statuses, totals and times' {
        $events[2]['status'] | Should Be 'ok'
        $events[4]['status'] | Should Be 'failed'
        $events[1]['total'] | Should Be 2
        $events[-1]['failed'] | Should Be 1
        foreach ($e in $events) { $e['time'] | Should Match 'Z$' }
    }
    It 'does not stop the snapshot when the progress file is locked' {
        # Review 007: progress is not data - a reader or antivirus holding the file must not cost the snapshot.
        $lockedDir = Join-Path $TestDrive 'progress-locked'
        $null = New-Item -ItemType Directory -Path $lockedDir
        $lock = [IO.File]::Open((Join-Path $lockedDir 'progress.jsonl'), 'Create', 'ReadWrite', 'None')
        try { $result = & $orchestrator -OutputDirectory $lockedDir -Modules 'fixture-ok' -CollectorPath $fixtures -TimeoutSec 30 }
        finally { $lock.Dispose() }
        Test-Path (Join-Path $lockedDir 'snapshot.json') | Should Be $true
        $snapshot = ConvertFrom-CollectorJson ([IO.File]::ReadAllText((Join-Path $lockedDir 'snapshot.json'), [Text.Encoding]::UTF8))
        $snapshot['modules']['fixture-ok']['status'] | Should Be 'ok'
    }
}

Describe 'Invoke-Snapshot: elevatedAsOtherUser (D-015)' {
    $orchestrator = Join-Path (Get-RepoRoot) 'collectors\Invoke-Snapshot.ps1'
    $fixtures = Join-Path $PSScriptRoot 'fixtures'
    function Get-HostFlag([string] $Sid) {
        $outDir = Join-Path $TestDrive ('sid-' + [guid]::NewGuid().ToString('N'))
        $params = @{ OutputDirectory = $outDir; Modules = 'fixture-ok'; CollectorPath = $fixtures; TimeoutSec = 30 }
        if ($Sid) { $params['LaunchingUserSid'] = $Sid }
        $result = & $orchestrator @params
        $snapshot = ConvertFrom-CollectorJson ([IO.File]::ReadAllText($result.Path, [Text.Encoding]::UTF8))
        , @($snapshot['host'].ContainsKey('elevatedAsOtherUser'), $snapshot['host']['elevatedAsOtherUser'], [IO.File]::ReadAllText($result.Path))
    }

    It 'is false when the launching user runs it' {
        $r = Get-HostFlag ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
        $r[1] | Should Be $false
    }
    It 'is true under another account and the SID is not stored' {
        $fake = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        $r = Get-HostFlag $fake
        $r[1] | Should Be $true
        $r[2] | Should Not Match ([regex]::Escape($fake))
    }
    It 'is null when the launching user is unknown' {
        $r = Get-HostFlag $null
        $r[0] | Should Be $true
        $null -eq $r[1] | Should Be $true
    }
}
