# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/system.ps1 against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force

Describe 'Collector: system' {
    $script = Join-Path (Get-RepoRoot) 'collectors\system.ps1'
    $env = Invoke-CollectorScript -Path $script -OutFile (Join-Path $TestDrive 'system.json')
    $data = $env['data']

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'system') -join '; ' | Should Be ''
    }
    It 'is ok without admin rights (no admin-only sources)' {
        $env['status'] | Should Be 'ok'
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'has every section' {
        foreach ($key in 'os', 'computer', 'boot', 'pendingReboot', 'hotfixes', 'networkProfiles') {
            $data.ContainsKey($key) | Should Be $true
        }
    }
    It 'reports the build from the registry and derives the family' {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $data['os']['build'] | Should Be ([int]$cv.CurrentBuild)
        $data['os']['ubr'] | Should Be $cv.UBR
        $expected = if ([int]$cv.CurrentBuild -ge 22000) { 'Windows 11' } else { 'Windows 10' }
        $data['os']['family'] | Should Be $expected
        $data['os']['architecture'] | Should Match '^(x64|x86|arm64)$'
    }
    It 'writes dates as ISO 8601 UTC' {
        $data['os']['installDate'] | Should Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$'
        $data['boot']['lastBootUpTime'] | Should Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$'
        $data['boot']['uptimeSec'] -gt 0 | Should Be $true
    }
    It 'lists hotfixes as an array with parsed dates, newest first' {
        , $data['hotfixes'] | Should BeOfType [object[]]
        $dates = @($data['hotfixes'] | Where-Object { $_['installedOn'] } | ForEach-Object { $_['installedOn'] })
        foreach ($h in $data['hotfixes']) {
            $h['id'] | Should Match '^KB\d+$'
            if ($h['installedOnRaw'] -match '^\d{1,2}/\d{1,2}/\d{4}$') { $h['installedOn'] | Should Match '^\d{4}-\d\d-\d\d$' }
        }
        ($dates -join ',') | Should Be ((@($dates | Sort-Object -Descending)) -join ',')
    }
    It 'lists network profiles with enums as strings' {
        , $data['networkProfiles'] | Should BeOfType [object[]]
        foreach ($p in $data['networkProfiles']) {
            $p['category'] | Should Match '^(Public|Private|DomainAuthenticated)$'
            $p['ipv4Connectivity'] | Should Match '^[A-Za-z]+$'
            $p['interfaceIndex'] -is [int] | Should Be $true
        }
    }
    It 'pending reboot flags are booleans' {
        foreach ($key in 'componentServicing', 'windowsUpdate', 'fileRenameOperations') {
            $data['pendingReboot'][$key] -is [bool] | Should Be $true
        }
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 30000 | Should Be $true
    }
}
