# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/connections.ps1: address classes and the D-009 split
# on known input, and the collector against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\connections.ps1'

Describe 'connections helpers' {
    . $collector

    It 'classifies addresses' -TestCases @(
        @{ in = '0.0.0.0'; out = 'unspecified' }
        @{ in = '127.0.0.1'; out = 'loopback' }
        @{ in = '10.1.2.3'; out = 'private' }
        @{ in = '172.16.0.1'; out = 'private' }
        @{ in = '172.31.255.1'; out = 'private' }
        @{ in = '172.32.0.1'; out = 'public' }
        @{ in = '192.168.31.1'; out = 'private' }
        @{ in = '100.64.0.1'; out = 'cgnat' }
        @{ in = '100.128.0.1'; out = 'public' }
        @{ in = '169.254.10.20'; out = 'linkLocal' }
        @{ in = '224.0.0.251'; out = 'multicast' }
        @{ in = '255.255.255.255'; out = 'broadcast' }
        @{ in = '203.0.113.5'; out = 'public' }
        @{ in = '::'; out = 'unspecified' }
        @{ in = '::1'; out = 'loopback' }
        @{ in = 'fe80::1%12'; out = 'linkLocal' }
        @{ in = 'fd00::1'; out = 'uniqueLocal' }
        @{ in = 'ff02::fb'; out = 'multicast' }
        @{ in = 'fec0:0:0:ffff::1'; out = 'private' }
        @{ in = '2001:db8::1'; out = 'public' }
        @{ in = '::ffff:192.168.1.1'; out = 'private' }
        @{ in = '::ffff:198.51.100.1'; out = 'public' }
    ) {
        param($in, $out)
        Get-AddressClass $in | Should BeExactly $out
    }
    It 'returns null for empty or invalid input' {
        $null -eq (Get-AddressClass '') | Should Be $true
        $null -eq (Get-AddressClass 'not-an-ip') | Should Be $true
    }

    $sample = @(
        @{ state = 'Established'; localAddress = '192.0.2.10'; localPort = 50001; remoteAddress = '198.51.100.1'; remotePort = 443; processId = 10; process = 'browser' }
        @{ state = 'Established'; localAddress = '192.0.2.10'; localPort = 50002; remoteAddress = '198.51.100.1'; remotePort = 443; processId = 10; process = 'browser' }
        @{ state = 'TimeWait'; localAddress = '192.0.2.10'; localPort = 50003; remoteAddress = '198.51.100.2'; remotePort = 443; processId = 10; process = 'browser' }
        @{ state = 'Established'; localAddress = '192.0.2.10'; localPort = 50004; remoteAddress = '203.0.113.9'; remotePort = 8443; processId = 20; process = 'xray' }
        @{ state = 'Established'; localAddress = '127.0.0.1'; localPort = 50005; remoteAddress = '127.0.0.1'; remotePort = 10809; processId = 30; process = 'app' }
        @{ state = 'Established'; localAddress = '192.168.1.5'; localPort = 50006; remoteAddress = '192.168.1.1'; remotePort = 53; processId = 40; process = 'svchost' }
        @{ state = 'Bound'; localAddress = '0.0.0.0'; localPort = 50007; remoteAddress = '0.0.0.0'; remotePort = 0; processId = 50; process = $null }
    )
    $split = Split-TcpConnections -Connections $sample
    $json = ConvertTo-CollectorJson @{ entries = $split.Entries; public = $split.Public }

    It 'keeps non-public connections in full' {
        $split.Entries.Count | Should Be 3
        ($split.Entries | ForEach-Object { $_['remoteClass'] }) -join ',' | Should Be 'loopback,private,unspecified'
        $split.Entries[0]['remoteAddress'] | Should Be '127.0.0.1'
        $split.Entries[1]['remotePort'] | Should Be 53
    }
    It 'counts public connections per process, local address and remote port' {
        $split.Public.Count | Should Be 2
        $b = $split.Public[0]
        $b['process'] | Should Be 'browser'
        $b['remotePort'] | Should Be 443
        $b['connections'] | Should Be 3
        $b['uniqueRemoteAddresses'] | Should Be 2
        ($b['byState'] | ForEach-Object { $_['state'] + '=' + $_['count'] }) -join ',' | Should Be 'Established=2,TimeWait=1'
        $split.Public[1]['uniqueRemoteAddresses'] | Should Be 1
    }
    It 'never returns public remote addresses (D-009)' {
        $json | Should Not Match '198\.51\.100|203\.0\.113'
        $json | Should Match '192\.0\.2\.10'
    }
    It 'handles no connections' {
        $empty = Split-TcpConnections -Connections @()
        $empty.Entries.Count | Should Be 0
        $empty.Public.Count | Should Be 0
    }
}

Describe 'Collector: connections' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'connections.json')
    $data = $env['data']

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'connections') -join '; ' | Should Be ''
    }
    It 'is ok without admin rights' {
        $env['status'] | Should Be 'ok'
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'lists TCP listeners and UDP endpoints with processes' {
        , $data['tcpListeners'] | Should BeOfType [object[]]
        , $data['udpEndpoints'] | Should BeOfType [object[]]
        $data['tcpListeners'].Count -gt 0 | Should Be $true
        foreach ($l in @($data['tcpListeners']) + @($data['udpEndpoints'])) {
            $l['localPort'] -is [int] | Should Be $true
            $l['processId'] -is [int] | Should Be $true
        }
        # System (pid 4) listens on 445/139 or similar on every Windows.
        @($data['tcpListeners'] | Where-Object { $_['processId'] -eq 4 }).Count -gt 0 | Should Be $true
    }
    It 'stores no public remote address (D-009)' {
        foreach ($c in $data['tcpConnections']) {
            $c['remoteClass'] | Should Not Be 'public'
            $c['remoteClass'] | Should Not BeNullOrEmpty
        }
        foreach ($p in $data['publicConnections']) {
            $p.Keys -contains 'remoteAddress' | Should Be $false
            $p['uniqueRemoteAddresses'] -le $p['connections'] | Should Be $true
        }
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 30000 | Should Be $true
    }
}
