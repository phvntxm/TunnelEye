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
