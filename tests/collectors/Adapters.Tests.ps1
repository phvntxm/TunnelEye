# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/adapters.ps1: pnputil parser on a localized sample and
# the collector against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\adapters.ps1'

Describe 'ConvertFrom-PnputilDrivers' {
    . $collector
    $text = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'fixtures\pnputil-enum-drivers-ru.txt'), [Text.Encoding]::UTF8)
    $parsed = ConvertFrom-PnputilDrivers -Text $text
    $byName = @{}
    foreach ($p in $parsed.Packages) { $byName[$p.publishedName] = $p }

    It 'keeps only Net-class packages, by class GUID in any case' {
        (@($parsed.Packages | ForEach-Object { $_.publishedName }) -join ',') | Should Be 'oem23.inf,oem36.inf,oem77.inf'
    }
    It 'takes fields by position regardless of label language' {
        $p = $byName['oem23.inf']
        $p.originalName | Should Be 'ftsvnic.inf'
        $p.provider | Should Be 'Fortinet Inc'
        $p.classGuid | Should Be '{4d36e972-e325-11ce-bfc1-08002be10318}'
        $p.signer | Should Be 'Microsoft Windows Hardware Compatibility Publisher'
    }
    It 'parses MM/dd/yyyy and dd.MM.yyyy dates' {
        $byName['oem23.inf'].driverDate | Should Be '2024-03-19'
        $byName['oem23.inf'].driverVersion | Should Be '17.47.11.597'
        $byName['oem36.inf'].driverDate | Should Be '2021-04-16'
    }
    It 'keeps a package with an unknown date format, date null' {
        $null -eq $byName['oem77.inf'].driverDate | Should Be $true
        $byName['oem77.inf'].driverVersion | Should Be '9.24.2.601'
    }
    It 'counts malformed Net blocks and keeps their raw text' {
        $parsed.Unparsed | Should Be 1
        $parsed.Raw | Should Match 'broken\.inf'
        $parsed.Raw | Should Not Match 'nvhda'
    }
    It 'returns nothing for empty output' {
        $empty = ConvertFrom-PnputilDrivers -Text ''
        @($empty.Packages).Count | Should Be 0
        $empty.Unparsed | Should Be 0
    }
}

Describe 'Collector: adapters' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'adapters.json')
    $data = $env['data']
    $live = @(Get-NetAdapter -IncludeHidden)

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'adapters') -join '; ' | Should Be ''
    }
    It 'is ok without admin rights' {
        $env['status'] | Should Be 'ok'
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'includes every adapter, hidden ones too, sorted by index' {
        $data['adapters'].Count | Should Be $live.Count
        $indexes = @($data['adapters'] | ForEach-Object { $_['interfaceIndex'] })
        ($indexes -join ',') | Should Be ((@($indexes | Sort-Object)) -join ',')
        if (@($live | Where-Object Hidden).Count) {
            @($data['adapters'] | Where-Object { $_['hidden'] }).Count -gt 0 | Should Be $true
        }
    }
    It 'every adapter has the full set of fields with the right types' {
        foreach ($a in $data['adapters']) {
            $a['name'] | Should Not BeNullOrEmpty
            $a['status'] | Should Match '^[A-Za-z ]+$'
            $a['virtual'] -is [bool] | Should Be $true
            $a['driver'] -is [System.Collections.IDictionary] | Should Be $true
            , $a['bindings'] | Should BeOfType [object[]]
            , $a['advancedProperties'] | Should BeOfType [object[]]
            foreach ($key in 'provider', 'version', 'date', 'infName', 'isSigned', 'signer') {
                $a['driver'].ContainsKey($key) | Should Be $true
            }
            if ($a['driver']['date']) { $a['driver']['date'] | Should Match '^\d{4}-\d\d-\d\d$' }
        }
    }
    It 'joins driver signature for hardware adapters' {
        $hw = @($data['adapters'] | Where-Object { $_['hardwareInterface'] })
        foreach ($a in $hw) { $a['driver']['isSigned'] -is [bool] | Should Be $true }
    }
    It 'advanced property values are string arrays' {
        foreach ($a in $data['adapters']) {
            foreach ($p in $a['advancedProperties']) {
                , $p['registryValue'] | Should BeOfType [object[]]
            }
        }
    }
    It 'lists Net-class PnP devices and driver packages' {
        , $data['devices'] | Should BeOfType [object[]]
        foreach ($d in $data['devices']) { $d['present'] -is [bool] | Should Be $true }
        , $data['driverPackages'] | Should BeOfType [object[]]
        foreach ($p in $data['driverPackages']) { $p['publishedName'] | Should Match '^oem\d+\.inf$' }
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 60000 | Should Be $true
    }
}
