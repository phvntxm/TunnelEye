# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/firewall.ps1: helpers and the WFP state parser on an
# anonymized fixture, and the collector against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\firewall.ps1'
$wfpFixture = Join-Path $PSScriptRoot 'fixtures\wfpstate-sample.xml'

Describe 'firewall helpers' {
    . $collector

    It 'splits flag enums into lists' {
        (ConvertTo-FlagList 'Domain, Private') -join '|' | Should Be 'Domain|Private'
        , (ConvertTo-FlagList 'Any') | Should BeOfType [object[]]
        (ConvertTo-FlagList $null).Count | Should Be 0
    }
    It 'turns filter values into string arrays' {
        , (ConvertTo-StringList '80') | Should BeOfType [object[]]
        (ConvertTo-StringList @('80', '443')) -join ',' | Should Be '80,443'
        (ConvertTo-StringList $null).Count | Should Be 0
    }
    It 'decodes Security Center product states' -TestCases @(
        @{ state = 266240; enabled = $true; upToDate = $true }
        @{ state = 397584; enabled = $true; upToDate = $false }
        @{ state = 393472; enabled = $false; upToDate = $true }
    ) {
        param($state, $enabled, $upToDate)
        $r = ConvertFrom-SecurityCenterState $state
        $r.enabled | Should Be $enabled
        $r.upToDate | Should Be $upToDate
    }
    It 'hides the user profile folder inside rule names' {
        Hide-UserProfilePath 'TCP Query User{0F}C:\users\someone\downloads\tool.exe' | Should BeExactly 'TCP Query User{0F}%USERPROFILE%\downloads\tool.exe'
        Hide-UserProfilePath 'D:\Games\Users\game.exe' | Should BeExactly 'D:\Games\Users\game.exe'
        $null -eq (Hide-UserProfilePath '') | Should Be $true
    }
}

Describe 'WFP state parser' {
    . $collector
    $doc = Read-WfpStateXml -Path $wfpFixture
    $wfp = ConvertFrom-WfpState -Document $doc
    $json = ConvertTo-CollectorJson $wfp

    It 'reads the <wfpstate> element of a multi-root file' {
        $doc.DocumentElement.Name | Should Be 'wfpstate'
    }
    It 'lists providers, sublayers, callouts and filters' {
        $wfp['providers'].Count | Should Be 2
        $wfp['subLayers'].Count | Should Be 2
        $wfp['callouts'].Count | Should Be 1
        $wfp['filters'].Count | Should Be 3
        $wfp['providerContextCount'] | Should Be 2
    }
    It 'decodes UTF-8 names' {
        # "Korporatsiya" in Cyrillic; the source stays ASCII-only.
        $expected = -join [char[]](0x41A, 0x43E, 0x440, 0x43F, 0x43E, 0x440, 0x430, 0x446, 0x438, 0x44F)
        $wfp['providers'][0]['name'] | Should Match ('^' + $expected + ' ')
    }
    It 'sorts filters by id and keeps their keys' {
        ($wfp['filters'] | ForEach-Object { $_['filterId'] }) -join ',' | Should Be '69999,70001,70002'
        $f = $wfp['filters'][2]
        $f['providerKey'] | Should Be '{22222222-2222-4222-8222-222222222222}'
        $f['layerKey'] | Should Be 'FWPM_LAYER_ALE_AUTH_CONNECT_V4'
        $f['subLayerKey'] | Should Be '{66666666-6666-4666-8666-666666666666}'
    }
    It 'links callout actions to the callout and only them' {
        $wfp['filters'][2]['action'] | Should Be 'FWP_ACTION_CALLOUT_TERMINATING'
        $wfp['filters'][2]['calloutKey'] | Should Be '{11111111-1111-4111-8111-111111111111}'
        $null -eq $wfp['filters'][1]['calloutKey'] | Should Be $true
        $wfp['callouts'][0]['calloutId'] | Should Be 301
    }
    It 'keeps weights as decimal strings, null when empty' {
        $wfp['filters'][1]['weight'] | Should BeExactly '12'
        $wfp['filters'][2]['weight'] | Should BeExactly '18446744073709551615'
        $null -eq $wfp['filters'][0]['weight'] | Should Be $true
        $wfp['filters'][0]['effectiveWeight'] | Should BeExactly '4'
        $null -eq $wfp['filters'][0]['providerKey'] | Should Be $true
    }
    It 'keeps condition fields and match types, not values' {
        $c = $wfp['filters'][1]['conditions']
        ($c | ForEach-Object { $_['fieldKey'] + '/' + $_['matchType'] }) -join ',' |
            Should Be 'FWPM_CONDITION_ALE_APP_ID/FWP_MATCH_EQUAL,FWPM_CONDITION_IP_REMOTE_ADDRESS/FWP_MATCH_RANGE'
        , $wfp['filters'][0]['conditions'] | Should BeOfType [object[]]
    }
    It 'never returns sessions, endpoints, condition values or the user name' {
        $json | Should Not Match 'someone'
        $json | Should Not Match 'S-1-5-21'
        $json | Should Not Match '203\.0\.113|198\.51\.100|192\.0\.2'
        $json | Should Not Match 'harddiskvolume'
        $wfp['filters'][1]['name'] | Should Match '%USERPROFILE%\\appdata'
    }
}

Describe 'Collector: firewall' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'firewall.json')
    $data = $env['data']
    $json = [IO.File]::ReadAllText((Join-Path $TestDrive 'firewall.json'), [Text.Encoding]::UTF8)

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'firewall') -join '; ' | Should Be ''
    }
    It 'is partial without admin rights only because of admin-only sources' {
        if ($env['elevated']) {
            $env['status'] | Should Be 'ok'
        }
        else {
            $env['status'] | Should Be 'partial'
            foreach ($e in $env['errors']) {
                $e['kind'] | Should Be 'AccessDenied'
                $e['source'] | Should Match '^(Get-NetFirewallPortFilter|Get-NetFirewallAddressFilter|netsh wfp show state)$'
            }
        }
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'reports the three firewall profiles' {
        ($data['profiles'] | ForEach-Object { $_['name'] }) -join ',' | Should Be 'Domain,Private,Public'
        foreach ($p in $data['profiles']) { $p['enabled'] -is [bool] | Should Be $true }
    }
    It 'lists every rule of the effective policy' {
        $data['rules'].Count | Should Be @(Get-NetFirewallRule -PolicyStore ActiveStore).Count
        foreach ($r in $data['rules']) {
            $r['enabled'] -is [bool] | Should Be $true
            , $r['profiles'] | Should BeOfType [object[]]
        }
    }
    It 'reports WFP only with admin rights' {
        if ($env['elevated']) {
            $data['wfp']['filters'].Count -gt 0 | Should Be $true
            $data['wfp']['providers'].Count -gt 0 | Should Be $true
        }
        else {
            $null -eq $data['wfp'] | Should Be $true
        }
    }
    It 'reports the firewall services' {
        ($data['services'] | ForEach-Object { $_['name'] }) -join ',' | Should Be 'BFE,mpssvc'
    }
    It 'never writes the user name and leaves no temp files' {
        $json | Should Not Match ([regex]::Escape($env:USERNAME))
        @(Get-ChildItem -Path ([IO.Path]::GetTempPath()) -Filter 'tunneleye-wfp-*.xml' -ErrorAction SilentlyContinue).Count | Should Be 0
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 60000 | Should Be $true
    }
}
