# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/wifi.ps1: netsh parsers on anonymized real output
# (Russian and English Windows 11, a Windows 10 layout) and the collector
# against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\wifi.ps1'
$fixtures = Join-Path $PSScriptRoot 'fixtures'
function Read-Fixture([string] $Name) { [IO.File]::ReadAllText((Join-Path $fixtures $Name), [Text.Encoding]::UTF8) }

Describe 'wifi helpers' {
    . $collector

    It 'normalizes bands' -TestCases @(
        @{ in = '5 GHz'; out = '5' }
        @{ in = '2.4 GHz'; out = '2.4' }
        @{ in = ('2,4 ' + (-join [char[]](0x413, 0x413, 0x446))); out = '2.4' }
        @{ in = '6 GHz [ 0 MHz - 0 MHz]'; out = '6' }
    ) {
        param($in, $out)
        ConvertTo-BandGHz $in | Should BeExactly $out
    }
    It 'rejects non-band values' {
        $null -eq (ConvertTo-BandGHz '802.11ac') | Should Be $true
        $null -eq (ConvertTo-BandGHz '44') | Should Be $true
    }
    It 'parses numbers with dot or comma' {
        ConvertTo-Number '292.5' | Should Be 292.5
        ConvertTo-Number '292,5' | Should Be 292.5
        $null -eq (ConvertTo-Number 'n/a') | Should Be $true
    }
}

Describe 'netsh wlan show interfaces' {
    . $collector

    It 'parses Russian and English Windows 11 output the same way' -TestCases @(
        @{ file = 'wlan-interfaces-ru.txt' }
        @{ file = 'wlan-interfaces-en.txt' }
    ) {
        param($file)
        $r = ConvertFrom-WlanInterfaces (Read-Fixture $file)
        $r.Interfaces.Count | Should Be 1
        $i = $r.Interfaces[0]
        $i['interfaceGuid'] | Should Be '{00000000-0000-4000-8000-0000000000a1}'
        $i['connected'] | Should Be $true
        $i['ssid'] | Should Be 'ExampleNet'
        $i['bandGHz'] | Should Be '5'
        $i['channel'] | Should Be 44
        $i['radioType'] | Should Be '802.11ac'
        $i['authentication'] | Should Be 'WPA2-Personal'
        $i['cipher'] | Should Be 'CCMP'
        $i['receiveRateMbps'] | Should Be 292.5
        $i['transmitRateMbps'] -gt 0 | Should Be $true
        $i['signalPercent'] -gt 0 | Should Be $true
        $i['rssiDbm'] -lt 0 | Should Be $true
        $r.Bssids.Count | Should Be 1
    }
    It 'parses the Windows 10 layout (channel after connection mode, no band, no RSSI)' {
        $r = ConvertFrom-WlanInterfaces (Read-Fixture 'wlan-interfaces-win10-en.txt')
        $i = $r.Interfaces[0]
        $i['channel'] | Should Be 6
        $i['receiveRateMbps'] | Should Be 72
        $i['transmitRateMbps'] | Should Be 72
        $i['signalPercent'] | Should Be 38
        $i['radioType'] | Should Be '802.11n'
        $null -eq $i['bandGHz'] | Should Be $true
        $null -eq $i['rssiDbm'] | Should Be $true
    }
    It 'returns no interfaces for unrelated text' {
        (ConvertFrom-WlanInterfaces "There is no wireless interface on the system.").Interfaces.Count | Should Be 0
    }
    It 'never returns the BSSID or the MAC address in the interface data' {
        $r = ConvertFrom-WlanInterfaces (Read-Fixture 'wlan-interfaces-ru.txt')
        (ConvertTo-CollectorJson $r.Interfaces) | Should Not Match '02:00:00:00:00'
    }
}

Describe 'netsh wlan show drivers' {
    . $collector

    It 'reads version, date, radio types and bands from <file>' -TestCases @(
        @{ file = 'wlan-drivers-ru.txt' }
        @{ file = 'wlan-drivers-en.txt' }
    ) {
        param($file)
        # The function returns the array itself (comma-wrapped): no @() here,
        # it would nest the array instead of copying it.
        $d = ConvertFrom-WlanDrivers (Read-Fixture $file)
        , $d | Should BeOfType [object[]]
        $d.Count | Should Be 1
        $d[0]['version'] | Should Be '24.30.1.1'
        $d[0]['date'] | Should Be '2026-03-03'
        ($d[0]['radioTypesSupported'] -join ' ') | Should Be '802.11b 802.11g 802.11n 802.11a 802.11ac 802.11ax'
        ($d[0]['bandsSupportedGHz'] -join ',') | Should Be '2.4,5,6'
        $d[0]['wpa3Supported'] | Should Be $true
    }
}

Describe 'netsh wlan show networks' {
    . $collector
    $own = (ConvertFrom-WlanInterfaces (Read-Fixture 'wlan-interfaces-ru.txt')).Bssids

    It 'lists access points without names or addresses' {
        $n = ConvertFrom-WlanNetworks -Text (Read-Fixture 'wlan-networks-ru.txt') -ConnectedBssids $own
        $n['networkCount'] | Should Be 2
        $n['bss'].Count | Should Be 2
        $json = ConvertTo-CollectorJson $n
        $json | Should Not Match 'NeighborNet|ExampleNet|02:00:00'
    }
    It 'reads band, channel, signal, radio type and BSS load' {
        $n = ConvertFrom-WlanNetworks -Text (Read-Fixture 'wlan-networks-ru.txt') -ConnectedBssids $own
        $b24 = $n['bss'][0]
        $b24['bandGHz'] | Should Be '2.4'
        $b24['channel'] | Should Be 9
        $b24['signalPercent'] | Should Be 50
        $b24['radioType'] | Should Be '802.11n'
        $b24['channelUtilizationPercent'] | Should Be 30
        $b24['connectedStations'] | Should Be 0
        $b24['connected'] | Should Be $false
        $b5 = $n['bss'][1]
        $b5['channel'] | Should Be 44
        $b5['channelUtilizationPercent'] | Should Be 15
        $b5['connectedStations'] | Should Be 5
        $b5['connected'] | Should Be $true
    }
    It 'reads the English layout with a space before the percent sign' {
        $n = ConvertFrom-WlanNetworks -Text (Read-Fixture 'wlan-networks-en.txt') -ConnectedBssids @()
        $n['bss'][0]['channelUtilizationPercent'] | Should Be 15
        $n['bss'][0]['channel'] | Should Be 44
    }
    It 'handles an empty scan' {
        $n = ConvertFrom-WlanNetworks -Text '' -ConnectedBssids @()
        $n['networkCount'] | Should Be 0
        , $n['bss'] | Should BeOfType [object[]]
    }
}

Describe 'Collector: wifi' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'wifi.json')
    $data = $env['data']
    $json = [IO.File]::ReadAllText((Join-Path $TestDrive 'wifi.json'), [Text.Encoding]::UTF8)
    $hasWifi = $null -ne (Get-Service WlanSvc -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'wifi') -join '; ' | Should Be ''
    }
    It 'is ok on a machine with Wi-Fi, skipped without it' {
        if ($hasWifi -and $env['status'] -ne 'skipped') {
            $env['status'] | Should Be 'ok'
        }
        else {
            $env['status'] | Should Be 'skipped'
        }
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'reports interfaces with GUIDs matching the adapters module format' {
        if ($env['status'] -ne 'ok') { return }
        , $data['interfaces'] | Should BeOfType [object[]]
        foreach ($i in $data['interfaces']) {
            $i['interfaceGuid'] | Should Match '^\{[0-9a-f-]{36}\}$'
            $i['connected'] -is [bool] | Should Be $true
        }
    }
    It 'never writes MAC addresses or BSSIDs' {
        $json | Should Not Match '([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 30000 | Should Be $true
    }
}
