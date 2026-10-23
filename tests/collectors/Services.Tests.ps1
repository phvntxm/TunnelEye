# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/services.ps1: helpers on known input and the
# collector against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\services.ps1'

Describe 'services helpers' {
    . $collector

    It 'maps accounts to classes without names' -TestCases @(
        @{ in = 'LocalSystem'; out = 'localSystem' }
        @{ in = 'NT AUTHORITY\LocalService'; out = 'localService' }
        @{ in = 'NT AUTHORITY\NETWORK SERVICE'; out = 'networkService' }
        @{ in = 'S-1-5-18'; out = 'localSystem' }
        @{ in = 'NT SERVICE\TrustedInstaller'; out = 'virtualService' }
        @{ in = 'BUILTIN\Users'; out = 'users' }
        @{ in = 'S-1-5-32-544'; out = 'administrators' }
        @{ in = 'someone'; out = 'userAccount' }
        @{ in = 'EXAMPLE-PC\someone'; out = 'userAccount' }
        @{ in = '.\svc_account'; out = 'userAccount' }
    ) {
        param($in, $out)
        Get-AccountClass $in | Should BeExactly $out
    }
    It 'returns null for an empty account' {
        $null -eq (Get-AccountClass '') | Should Be $true
        $null -eq (Get-AccountClass $null) | Should Be $true
    }
    It 'reads the Task Manager startup state' {
        Get-StartupApprovedState ([byte[]](2, 0, 0, 0)) | Should Be $true
        Get-StartupApprovedState ([byte[]](6, 0, 0, 0)) | Should Be $true
        Get-StartupApprovedState ([byte[]](3, 0, 0, 0)) | Should Be $false
        Get-StartupApprovedState ([byte[]](7, 0, 0, 0)) | Should Be $false
        Get-StartupApprovedState $null | Should Be $true
    }
    It 'hides user SIDs in task folders' {
        Hide-UserProfilePath '\SoftLanding\S-1-5-21-1111111111-2222222222-3333333333-1001\' | Should BeExactly '\SoftLanding\%USERSID%\'
        Hide-UserProfilePath 'S-1-15-2-1-2-3' | Should BeExactly 'S-1-15-2-1-2-3'
    }
    It 'reads image existence and vendor once per file' {
        $cache = @{}
        $a = Get-ImageInfo -CommandLine '%SystemRoot%\System32\svchost.exe -k netsvcs' -Cache $cache
        $b = Get-ImageInfo -CommandLine 'C:\Windows\system32\svchost.exe -k LocalService' -Cache $cache
        $a.imageExists | Should Be $true
        $a.hasArguments | Should Be $true
        $a.company | Should Match 'Microsoft'
        $b.company | Should Be $a.company
        $cache.Count | Should Be 1
        $m = Get-ImageInfo -CommandLine '"C:\No\Such\Folder\tool.exe" /x' -Cache $cache
        $m.imageExists | Should Be $false
        $null -eq $m.company | Should Be $true
        $m.imagePath | Should BeExactly 'C:\No\Such\Folder\tool.exe'
    }
    It 'hides the profile folder in image paths' {
        $r = Get-ImageInfo -CommandLine '"C:\Users\someone\AppData\Local\App\app.exe" --minimized' -Cache @{}
        $r.imagePath | Should BeExactly '%USERPROFILE%\AppData\Local\App\app.exe'
    }
}

Describe 'Collector: services' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'services.json')
    $data = $env['data']
    $json = [IO.File]::ReadAllText((Join-Path $TestDrive 'services.json'), [Text.Encoding]::UTF8)

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'services') -join '; ' | Should Be ''
    }
    It 'is ok without admin rights' {
        $env['status'] | Should Be 'ok'
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'lists every service and driver' {
        $data['services'].Count | Should Be @(Get-CimInstance Win32_Service).Count
        $data['drivers'].Count | Should Be @(Get-CimInstance Win32_SystemDriver).Count
    }
    It 'stores account classes only' {
        foreach ($s in $data['services']) {
            if ($null -ne $s['account']) {
                $s['account'] | Should Match '^(localSystem|localService|networkService|virtualService|interactive|users|administrators|authenticatedUsers|userAccount)$'
            }
        }
    }
    It 'accounts for every scheduled task' {
        $t = $data['scheduledTasks']
        ($t['thirdParty'].Count + $t['microsoft']['total']) | Should Be @(Get-ScheduledTask).Count
        $sum = 0; foreach ($s in $t['microsoft']['byState']) { $sum += $s['count'] }
        $sum | Should Be $t['microsoft']['total']
        foreach ($task in $t['thirdParty']) {
            $task['taskPath'] | Should Not Match '^\\Microsoft\\'
            , $task['actions'] | Should BeOfType [object[]]
            , $task['triggers'] | Should BeOfType [object[]]
        }
    }
    It 'lists autostart entries with a location and a state' {
        , $data['autostart'] | Should BeOfType [object[]]
        foreach ($a in $data['autostart']) {
            $a['location'] | Should Match '^(HK(LM|CU)\\Run(Once)?( \(32-bit\))?|Startup \((user|all users)\))$'
            $a['enabled'] -is [bool] | Should Be $true
        }
    }
    It 'lists NDIS filters with consistent binding counts' {
        , $data['ndisFilters'] | Should BeOfType [object[]]
        foreach ($f in $data['ndisFilters']) {
            $f['componentId'] | Should Not BeNullOrEmpty
            $f['bindingsEnabled'] -le $f['bindingsTotal'] | Should Be $true
        }
    }
    It 'never writes the user name, user SIDs or the computer name' {
        $json | Should Not Match ([regex]::Escape($env:USERNAME))
        $json | Should Not Match 'S-1-5-21-'
        $json | Should Not Match ([regex]::Escape($env:COMPUTERNAME))
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 60000 | Should Be $true
    }
}
