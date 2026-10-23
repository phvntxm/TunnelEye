# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/dns-proxy.ps1: parsers on known input and the
# collector against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\dns-proxy.ps1'

function New-SettingsBlob {
    # Builds a DefaultConnectionSettings-style blob: version, counter, flags,
    # then length-prefixed ASCII strings.
    param([int] $Flags, [string[]] $Strings)
    $ms = New-Object IO.MemoryStream
    $w = New-Object IO.BinaryWriter($ms)
    $w.Write([int]0x46); $w.Write([int]1); $w.Write([int]$Flags)
    foreach ($s in $Strings) {
        $bytes = [Text.Encoding]::ASCII.GetBytes($s)
        $w.Write([int]$bytes.Length); $w.Write($bytes)
    }
    $w.Flush()
    , $ms.ToArray()
}

Describe 'dns-proxy helpers' {
    . $collector

    It 'strips user:password@ from proxy strings' -TestCases @(
        @{ in = 'http://user:secret@10.0.0.1:3128'; out = 'http://10.0.0.1:3128'; removed = $true }
        @{ in = 'http=bob:pw@proxy:80;https=proxy:443'; out = 'http=proxy:80;https=proxy:443'; removed = $true }
        @{ in = 'user@proxy.corp:8080'; out = 'proxy.corp:8080'; removed = $true }
        @{ in = 'http://127.0.0.1:10809'; out = 'http://127.0.0.1:10809'; removed = $false }
    ) {
        param($in, $out, $removed)
        $r = Remove-UrlCredential $in
        $r.value | Should BeExactly $out
        $r.userInfoRemoved | Should Be $removed
    }
    It 'keeps null and empty as null' {
        $null -eq (Remove-UrlCredential $null).value | Should Be $true
        $null -eq (Remove-UrlCredential '').value | Should Be $true
    }
    It 'decodes the real WinHttpSettings blob (direct access) of a Windows 11 machine' {
        $bytes = [byte[]](0x18, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        $r = ConvertFrom-ConnectionSettingsBlob $bytes
        $r.proxyEnabled | Should Be $false
        $null -eq $r.proxyServer | Should Be $true
        $null -eq $r.bypassList | Should Be $true
    }
    It 'decodes proxy, bypass, PAC URL and flags' {
        $r = ConvertFrom-ConnectionSettingsBlob (New-SettingsBlob -Flags 0x0F -Strings 'proxy:8080', '<local>', 'http://wpad/wpad.dat')
        $r.proxyEnabled | Should Be $true
        $r.autoConfigEnabled | Should Be $true
        $r.autoDetect | Should Be $true
        $r.proxyServer | Should Be 'proxy:8080'
        $r.bypassList | Should Be '<local>'
        $r.autoConfigUrl | Should Be 'http://wpad/wpad.dat'
    }
    It 'survives truncated or missing blobs' {
        $null -eq (ConvertFrom-ConnectionSettingsBlob $null) | Should Be $true
        $null -eq (ConvertFrom-ConnectionSettingsBlob ([byte[]](1, 2, 3))) | Should Be $true
        $broken = New-SettingsBlob -Flags 3 -Strings 'proxy:8080'
        $broken = $broken[0..($broken.Length - 3)]
        $r = ConvertFrom-ConnectionSettingsBlob $broken
        $r.proxyEnabled | Should Be $true
        $null -eq $r.proxyServer | Should Be $true
    }
    It 'parses hosts lines: comments, inline comments, several names' {
        $text = "# comment`r`n`r`n127.0.0.1  localhost`r`n0.0.0.0 ads.example ads2.example # blocked`r`n   ::1 ip6-localhost`r`nbadline"
        $entries = @(ConvertFrom-HostsFile $text)
        $entries.Count | Should Be 3
        $entries[1].address | Should Be '0.0.0.0'
        ($entries[1].names -join ',') | Should Be 'ads.example,ads2.example'
        , $entries[2].names | Should BeOfType [object[]]
    }
    It 'recognizes sinkhole addresses' {
        foreach ($a in '0.0.0.0', '127.0.0.1', '127.1.2.3', '::', '::1') { Test-SinkholeAddress $a | Should Be $true }
        foreach ($a in '192.168.1.1', '8.8.8.8', '2001:db8::1', $null) { Test-SinkholeAddress $a | Should Be $false }
    }
    It 'names address families' {
        Get-AddressFamilyName 2 | Should Be 'IPv4'
        Get-AddressFamilyName 23 | Should Be 'IPv6'
    }
}

Describe 'Collector: dns-proxy' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'dns-proxy.json')
    $data = $env['data']
    $json = [IO.File]::ReadAllText((Join-Path $TestDrive 'dns-proxy.json'), [Text.Encoding]::UTF8)

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'dns-proxy') -join '; ' | Should Be ''
    }
    It 'is ok without admin rights' {
        $env['status'] | Should Be 'ok'
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'lists DNS servers per interface and family' {
        $data['dnsServers'].Count | Should Be @(Get-DnsClientServerAddress).Count
        foreach ($s in $data['dnsServers']) {
            $s['addressFamily'] | Should Match '^IPv(4|6)$'
            , $s['serverAddresses'] | Should BeOfType [object[]]
        }
    }
    It 'reports DoH: known servers on Windows 11, null on Windows 10' {
        if (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
            , $data['doh']['knownServers'] | Should BeOfType [object[]]
        }
        else {
            $null -eq $data['doh']['knownServers'] | Should Be $true
        }
        , $data['doh']['interfaces'] | Should BeOfType [object[]]
        , $data['nrpt'] | Should BeOfType [object[]]
    }
    It 'keeps only aggregates of the DNS cache (D-003)' {
        $c = $data['dnsCache']
        $sumStatus = 0; foreach ($s in $c['byStatus']) { $sumStatus += $s['count'] }
        $sumType = 0; foreach ($t in $c['byType']) { $sumType += $t['count'] }
        $sumStatus | Should Be $c['total']
        $sumType | Should Be $c['total']
        foreach ($key in $c.Keys) { $key | Should Match '^(total|fromHosts|byStatus|byType|suspicious|suspiciousTruncated)$' }
    }
    It 'lists only sinkhole answers not from hosts as suspicious' {
        $hostNames = @{}
        foreach ($e in $data['hosts']['entries']) { foreach ($n in $e['names']) { $hostNames[$n] = $true } }
        foreach ($s in $data['dnsCache']['suspicious']) {
            $hostNames.ContainsKey($s['name']) | Should Be $false
            $s['data'] | Should Match '^(0\.0\.0\.0|127\.|::1?$)'
        }
        $data['dnsCache']['suspicious'].Count -le 200 | Should Be $true
    }
    It 'parses the hosts file' {
        $h = $data['hosts']
        $h['exists'] | Should Be $true
        $expected = @(Get-Content -LiteralPath $h['path'] | Where-Object { ($_ -replace '#.*$', '').Trim() -match '^\S+\s+\S+' }).Count
        $h['entries'].Count | Should Be $expected
    }
    It 'reads the user proxy as the registry has it' {
        $reg = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $expected = if ($null -eq $reg.ProxyEnable) { $null } else { [int]$reg.ProxyEnable -eq 1 }
        $data['proxy']['user']['proxyEnable'] | Should Be $expected
        $data['proxy']['winhttp']['direct'] -is [bool] | Should Be $true
        , $data['proxy']['environment'] | Should BeOfType [object[]]
    }
    It 'never writes credentials in proxy strings' {
        $json | Should Not Match '://[^/"@\s]+:[^/"@\s]+@'
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 30000 | Should Be $true
    }
}
