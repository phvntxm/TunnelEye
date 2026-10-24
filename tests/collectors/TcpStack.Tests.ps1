# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/tcp-stack.ps1: helpers on known input and the
# collector against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\tcp-stack.ps1'

Describe 'tcp-stack helpers' {
    . $collector

    It 'converts registry values' {
        ConvertTo-TweakValue 2 | Should Be 2
        ConvertTo-TweakValue ([int64]5000000000) | Should Be 5000000000
        ConvertTo-TweakValue ([byte[]](0xAB, 0x01)) | Should BeExactly 'ab01'
        ConvertTo-TweakValue 'x' | Should BeExactly 'x'
        $null -eq (ConvertTo-TweakValue $null) | Should Be $true
    }
    It 'parses netsh tcp global lines in order, ignoring headers' {
        $text = "Querying active state...`r`n`r`nTCP Global Parameters`r`n----------------------------------------------`r`n" +
            "Receive-Side Scaling State          : enabled `r`nReceive Window Auto-Tuning Level    : normal `r`nInitial RTO                         : 1000 `r`n"
        $r = ConvertFrom-NetshTcpGlobal $text
        $r.Count | Should Be 3
        $r[0]['label'] | Should BeExactly 'Receive-Side Scaling State'
        $r[0]['value'] | Should BeExactly 'enabled'
        $r[2]['value'] | Should BeExactly '1000'
    }
    It 'parses localized labels the same way' {
        # Cyrillic label built from code points: sources stay ASCII-only.
        $label = -join [char[]](0x421, 0x43E, 0x441, 0x442, 0x43E, 0x44F, 0x43D, 0x438, 0x435)
        $r = ConvertFrom-NetshTcpGlobal ("$label  : enabled")
        $r[0]['label'] | Should BeExactly $label
        (ConvertFrom-NetshTcpGlobal '').Count | Should Be 0
    }
    It 'reads only allow-listed registry values' {
        $r = Get-RegistryTweaks -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Names @('NoSuchTweakValue')
        , $r | Should BeOfType [object[]]
        $r.Count | Should Be 0
        (Get-RegistryTweaks -Path 'HKLM:\SOFTWARE\NoSuchKeyForTunnelEye' -Names @('X')).Count | Should Be 0
    }
}

Describe 'Collector: tcp-stack' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'tcp-stack.json')
    $data = $env['data']
    $json = [IO.File]::ReadAllText((Join-Path $TestDrive 'tcp-stack.json'), [Text.Encoding]::UTF8)

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'tcp-stack') -join '; ' | Should Be ''
    }
    It 'is partial without admin rights only because of transport filters' {
        if ($env['elevated']) {
            $env['status'] | Should Be 'ok'
            , $data['transportFilters'] | Should BeOfType [object[]]
        }
        else {
            $env['status'] | Should Be 'partial'
            ($env['errors'] | ForEach-Object { $_['source'] + '=' + $_['kind'] }) -join ',' | Should Be 'Get-NetTransportFilter=AccessDenied'
            $null -eq $data['transportFilters'] | Should Be $true
        }
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'reports the TCP setting templates' {
        $names = @($data['settings'] | ForEach-Object { $_['settingName'] })
        $names -contains 'Internet' | Should Be $true
        $internet = $data['settings'] | Where-Object { $_['settingName'] -eq 'Internet' }
        $internet['congestionProvider'] | Should Not BeNullOrEmpty
        $internet['autoTuningLevelLocal'] | Should Not BeNullOrEmpty
    }
    It 'reports global offloads and netsh values' {
        $data['offload']['receiveSideScaling'] | Should Match '^(Enabled|Disabled)$'
        $data['netshGlobal']['values'].Count -gt 0 | Should Be $true
        $data['netshGlobal']['raw'] | Should Not BeNullOrEmpty
    }
    It 'never collects the host name, domain or DNS settings of the Tcpip key' {
        foreach ($scope in $data['registry']['global']) {
            foreach ($v in $scope['values']) { $v['name'] | Should Not Match '^(Hostname|NV Hostname|Domain|NameServer|DhcpNameServer|SearchList|ICSDomain)$' }
        }
        $json | Should Not Match ([regex]::Escape($env:COMPUTERNAME))
    }
    It 'keys interface tweaks by interface GUID' {
        foreach ($i in $data['registry']['interfaces']) {
            $i['interfaceGuid'] | Should Match '^\{[0-9a-f-]{36}\}$'
            $i['addressFamily'] | Should Match '^IPv(4|6)$'
        }
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 30000 | Should Be $true
    }
}
