# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/connectivity.ps1. Logic runs on fake network
# functions; the live run is local only. External tests on the live network
# run only with $env:TUNNELEYE_TEST_EXTERNAL = '1', set by the owner (D-002).

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\connectivity.ps1'

function New-FakeNet {
    # Fake network functions that record every probed address. $Ping:
    # param($Address, $Size, $Ttl, $DontFragment) -> status string.
    param([scriptblock] $Ping, [scriptblock] $Dns, [scriptblock] $Tcp, [scriptblock] $System)
    $calls = [System.Collections.Generic.List[string]]::new()
    if (-not $Ping) { $Ping = { param($a, $s, $t, $df) 'Success' } }
    if (-not $Dns) { $Dns = { param($srv, $n, $type) @{ status = 'answer'; rcode = 0; addresses = @('203.0.113.10'); rttMs = 5 } } }
    if (-not $Tcp) { $Tcp = { param($h, $p) @{ status = 'open' } } }
    if (-not $System) { $System = { param($n) @{ status = 'answer'; addresses = @('203.0.113.10'); rttMs = 1 } } }
    $net = @{
        calls = $calls
        ping  = { param($Address, $Size, $Ttl, $DontFragment, $TimeoutMs) $calls.Add("ping:$Address"); @{ status = (& $Ping $Address $Size $Ttl $DontFragment); rttMs = 1; address = $Address } }.GetNewClosure()
        dns   = { param($Server, $Name, $Type, $TimeoutMs) $calls.Add("dns:$Server"); & $Dns $Server $Name $Type }.GetNewClosure()
        tcp   = { param($HostName, $Port, $TimeoutMs) $calls.Add("tcp:$HostName"); & $Tcp $HostName $Port }.GetNewClosure()
        system = { param($Name, $TimeoutMs) $calls.Add("system:$Name"); & $System $Name }.GetNewClosure()
        route = { param($Address) @{ interfaceIndex = 7; interfaceAlias = 'Test' } }
    }
    $net
}

function Get-ProbedAddresses {
    param($Net)
    @($Net.calls | Where-Object { $_ -notlike 'system:*' } | ForEach-Object { ($_ -split ':', 2)[1] -replace '%.*$', '' })
}

Describe 'connectivity: target policy (D-002)' {
    . $collector

    It 'allows local addresses without consent' -TestCases @(
        @{ a = '192.168.1.1' }, @{ a = '10.0.0.1' }, @{ a = '127.0.0.1' }, @{ a = 'fe80::1' }, @{ a = 'fd00::53' }, @{ a = 'localhost' }
    ) {
        param($a)
        (Test-TargetAllowed -Address $a -AllowExternal $false).allowed | Should Be $true
    }
    It 'needs consent for public, CGNAT and host names' -TestCases @(
        @{ a = '8.8.8.8' }, @{ a = '2001:db8::1' }, @{ a = '100.64.1.1' }, @{ a = 'proxy.example' }
    ) {
        param($a)
        $r = Test-TargetAllowed -Address $a -AllowExternal $false
        $r.allowed | Should Be $false
        $r.reason | Should Be 'externalNotAllowed'
        (Test-TargetAllowed -Address $a -AllowExternal $true).allowed | Should Be $true
    }
    It 'never probes multicast, broadcast or unspecified addresses' {
        foreach ($a in '224.0.0.251', '255.255.255.255', '0.0.0.0') {
            (Test-TargetAllowed -Address $a -AllowExternal $true).reason | Should Be 'invalidTarget'
        }
    }
    It 'treats a gateway as local whatever its class' {
        (Test-TargetAllowed -Address '203.0.113.1' -AllowExternal $false -Gateway).allowed | Should Be $true
    }
}

Describe 'connectivity: helpers' {
    . $collector

    It 'keeps only active default routes on interfaces that are up' {
        $routes = @(
            [pscustomobject]@{ DestinationPrefix = '0.0.0.0/0'; NextHop = '192.168.1.1'; InterfaceIndex = 3; InterfaceAlias = 'Wi-Fi'; Store = 'ActiveStore' }
            [pscustomobject]@{ DestinationPrefix = '0.0.0.0/0'; NextHop = '192.168.1.1'; InterfaceIndex = 3; InterfaceAlias = 'Wi-Fi'; Store = 'ActiveStore' }
            [pscustomobject]@{ DestinationPrefix = '0.0.0.0/0'; NextHop = '10.8.0.1'; InterfaceIndex = 9; InterfaceAlias = 'Old VPN'; Store = 'PersistentStore' }
            [pscustomobject]@{ DestinationPrefix = '0.0.0.0/0'; NextHop = '172.16.0.1'; InterfaceIndex = 5; InterfaceAlias = 'Down'; Store = 'ActiveStore' }
            [pscustomobject]@{ DestinationPrefix = '0.0.0.0/0'; NextHop = '0.0.0.0'; InterfaceIndex = 3; InterfaceAlias = 'Tun'; Store = 'ActiveStore' }
            [pscustomobject]@{ DestinationPrefix = '::/0'; NextHop = 'fe80::1'; InterfaceIndex = 3; InterfaceAlias = 'Wi-Fi'; Store = 'ActiveStore' }
        )
        $g = Select-ActiveGateways -Routes $routes -UpInterfaces @{ 3 = $true; 9 = $true }
        , $g | Should BeOfType [object[]]
        ($g | ForEach-Object { $_['address'] + '/' + $_['family'] }) -join ',' | Should Be '192.168.1.1/IPv4,fe80::1%3/IPv6'
        (Select-ActiveGateways -Routes @() -UpInterfaces @{}).Count | Should Be 0
    }

    It 'builds PTR names' {
        Get-ReverseName '192.168.1.1' | Should BeExactly '1.1.168.192.in-addr.arpa'
        Get-ReverseName '2001:db8::1' | Should BeExactly '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'
        Get-ReverseName 'fe80::1%12' | Should Match '\.8\.e\.f\.ip6\.arpa$'
    }
    It 'parses proxy strings and strips credentials' -TestCases @(
        @{ in = '127.0.0.1:8118'; out = '|127.0.0.1|8118' }
        @{ in = 'http=127.0.0.1:8080;https=127.0.0.1:8081'; out = 'http|127.0.0.1|8080,https|127.0.0.1|8081' }
        @{ in = 'http://user:secret@proxy.example:3128'; out = 'http|proxy.example|3128' }
        @{ in = 'socks=[::1]:1080'; out = 'socks|::1|1080' }
        @{ in = 'proxy.example'; out = '|proxy.example|' }
    ) {
        param($in, $out)
        ((ConvertFrom-ProxyString $in) | ForEach-Object { '{0}|{1}|{2}' -f $_.scheme, $_.host, $_.port }) -join ',' | Should BeExactly $out
    }
    It 'returns no proxies for an empty value' {
        (ConvertFrom-ProxyString $null).Count | Should Be 0
    }
}

Describe 'connectivity: DNS wire format' {
    . $collector

    It 'builds a query packet' {
        $q = New-DnsQuery -Name 'a.b' -Type 1 -Id 0x1234
        ([BitConverter]::ToString($q)) | Should BeExactly '12-34-01-00-00-01-00-00-00-00-00-00-01-61-01-62-00-00-01-00-01'
        (New-DnsQuery -Name 'x.y.' -Type 12 -Id 1)[-3] | Should Be 12
    }

    $question = [byte[]](0x01, 0x61, 0x01, 0x62, 0x00, 0x00, 0x01, 0x00, 0x01)
    $a = [byte[]](0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 203, 0, 113, 7)
    $aaaa = [byte[]](0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
    $ok = [byte[]](0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00) + $question + $a + $aaaa
    $nx = [byte[]](0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + $question

    It 'reads A and AAAA answers with compressed names' {
        $r = ConvertFrom-DnsResponse -Bytes $ok -Id 0x1234
        $r.rcode | Should Be 0
        ($r.addresses -join ',') | Should Be '203.0.113.7,2001:db8::1'
        ConvertTo-DnsStatus $r | Should Be 'answer'
    }
    It 'reads NXDOMAIN and other response codes' {
        $r = ConvertFrom-DnsResponse -Bytes $nx -Id 0x1234
        ConvertTo-DnsStatus $r | Should Be 'nxdomain'
        ConvertTo-DnsStatus @{ rcode = 2 } | Should Be 'rcode'
        ConvertTo-DnsStatus $null | Should Be 'timeout'
    }
    It 'ignores packets that are not the answer to our query' {
        $null -eq (ConvertFrom-DnsResponse -Bytes $ok -Id 0x9999) | Should Be $true
        $null -eq (ConvertFrom-DnsResponse -Bytes ([byte[]](1, 2, 3)) -Id 0x0102) | Should Be $true
        $query = New-DnsQuery -Name 'a.b' -Id 0x1234
        $null -eq (ConvertFrom-DnsResponse -Bytes $query -Id 0x1234) | Should Be $true
    }
}

Describe 'connectivity: probes' {
    . $collector

    It 'summarizes a ping series' {
        $net = New-FakeNet
        $r = Invoke-PingSeries -Address '192.168.1.1' -Net $net -Count 4
        $r.received | Should Be 4
        $r.lossPercent | Should Be 0
        $r.status | Should Be 'Success'
        $dead = Invoke-PingSeries -Address '192.168.1.1' -Net (New-FakeNet -Ping { 'TimedOut' }) -Count 4
        $dead.received | Should Be 0
        $dead.lossPercent | Should Be 100
        $dead.status | Should Be 'TimedOut'
        $null -eq $dead.rttAvgMs | Should Be $true
    }
    It 'finds the path MTU by binary search with Do not Fragment' {
        $net = New-FakeNet -Ping { param($a, $s, $t, $df) if ($s -le 1400) { 'Success' } else { 'PacketTooBig' } }
        $r = Find-PathMtu -Address '203.0.113.1' -Net $net
        $r.maxPayload | Should Be 1400
        $r.mtu | Should Be 1428
        $r.status | Should Be 'ok'
    }
    It 'needs two probes when 1500 passes' {
        $r = Find-PathMtu -Address '192.168.1.1' -Net (New-FakeNet)
        $r.mtu | Should Be 1500
        $r.probes | Should Be 2
    }
    It 'retries a lost reply instead of counting the size as too big' {
        $state = @{ lost = $false }
        $net = New-FakeNet -Ping {
            param($a, $s, $t, $df)
            if ($s -eq 1472 -and -not $state.lost) { $state.lost = $true; return 'TimedOut' }
            'Success'
        }.GetNewClosure()
        $r = Find-PathMtu -Address '192.168.1.1' -Net $net
        $r.mtu | Should Be 1500
        $r.timeoutsCountedAsFail | Should Be 0
    }
    It 'counts persistent timeouts as not passing (silent drop in a tunnel)' {
        $net = New-FakeNet -Ping { param($a, $s, $t, $df) if ($s -le 1380) { 'Success' } else { 'TimedOut' } }
        $r = Find-PathMtu -Address '203.0.113.1' -Net $net
        $r.maxPayload | Should Be 1380
        $r.timeoutsCountedAsFail -gt 0 | Should Be $true
    }
    It 'does not search without an echo reply at all' {
        $net = New-FakeNet -Ping { 'TimedOut' }
        $r = Find-PathMtu -Address '203.0.113.1' -Net $net -Attempts 3
        $r.status | Should Be 'noEchoReply'
        $null -eq $r.mtu | Should Be $true
        $r.probes | Should Be 3
    }
    It 'traces to the target, leaving silent hops without address' {
        $net = New-FakeNet -Ping { param($a, $s, $t, $df) switch ($t) { 1 { 'TtlExpired' } 2 { 'TimedOut' } 3 { 'TtlExpired' } default { 'Success' } } }
        $r = Invoke-Trace -Address '203.0.113.1' -Net $net
        $r.status | Should Be 'reached'
        $r.hops.Count | Should Be 4
        $null -eq $r.hops[1]['address'] | Should Be $true
        $r.hops[2]['address'] | Should Be '203.0.113.1'
        # Intermediate hops have no RTT: .NET reports 0 for TtlExpired.
        $null -eq $r.hops[0]['rttMs'] | Should Be $true
        $r.hops[3]['rttMs'] | Should Be 1
    }
    It 'stops after five silent hops in a row' {
        $net = New-FakeNet -Ping { param($a, $s, $t, $df) if ($t -eq 1) { 'TtlExpired' } else { 'TimedOut' } }
        $r = Invoke-Trace -Address '203.0.113.1' -Net $net -StopAfterTimeouts 5
        $r.status | Should Be 'stoppedAfterTimeouts'
        $r.hops.Count | Should Be 6
    }
    It 'checks a DNS server with a PTR query; NXDOMAIN means it answers' {
        $types = [System.Collections.Generic.List[int]]::new()
        $net = New-FakeNet -Dns { param($s, $n, $t) $types.Add($t); @{ status = 'nxdomain'; rcode = 3; addresses = @(); rttMs = 2 } }.GetNewClosure()
        $r = Test-DnsServer -Address '192.168.1.1' -Net $net
        $r.responds | Should Be $true
        ($types -join ',') | Should Be '12'
        $silent = Test-DnsServer -Address '192.168.1.1' -Net (New-FakeNet -Dns { @{ status = 'timeout' } }) -Attempts 2
        $silent.responds | Should Be $false
    }
    It 'compares DNS answers across servers' {
        $results = @(
            [ordered]@{ server = 'A'; status = 'answer'; addresses = @('203.0.113.7') }
            [ordered]@{ server = 'B'; status = 'answer'; addresses = @('0.0.0.0') }
            [ordered]@{ server = 'C'; status = 'nxdomain'; addresses = @() }
            [ordered]@{ server = 'D'; status = 'timeout'; addresses = @() }
        )
        $c = Compare-DnsAnswers -Name 'www.example.com' -Results $results
        $c['distinctAnswerSets'] | Should Be 2
        ($c['sinkholeServers'] -join ',') | Should Be 'B'
        ($c['nxdomainServers'] -join ',') | Should Be 'C'
        ($c['failedServers'] -join ',') | Should Be 'D'
    }
}

Describe 'connectivity: orchestration' {
    . $collector

    $inventory = @{
        profiles           = @()
        systemProxyEnabled = $true
        gateways           = @(@{ address = '192.168.1.1'; family = 'IPv4'; interfaceIndex = 3; interfaceAlias = 'Wi-Fi' }, @{ address = 'fe80::1%3'; family = 'IPv6'; interfaceIndex = 3; interfaceAlias = 'Wi-Fi' })
        dnsServers         = @(
            @{ address = '192.168.1.1'; interfaceIndex = 3 }
            @{ address = '192.168.1.1'; interfaceIndex = 4 }
            @{ address = '8.8.8.8'; interfaceIndex = 3 }
            @{ address = 'fec0:0:0:ffff::1'; interfaceIndex = 5 }
        )
        proxies            = @(
            @{ source = 'user'; enabled = $true; scheme = $null; host = '127.0.0.1'; port = 8118 }
            @{ source = 'machine'; enabled = $false; scheme = 'http'; host = '203.0.113.5'; port = 3128 }
            @{ source = 'winhttp'; enabled = $true; scheme = $null; host = 'proxy.example'; port = 8080 }
            @{ source = 'user'; enabled = $true; scheme = $null; host = '127.0.0.1'; port = $null }
        )
        targets            = @{ ping = @('198.51.100.1'); dnsServers = @('198.51.100.53'); dnsNames = @('www.example.com'); trace = @('198.51.100.1'); mtu = @('198.51.100.1', '2001:db8::1'); userFile = $false }
    }

    It 'probes nothing outside the local network without consent' {
        $net = New-FakeNet
        $data = Invoke-ConnectivityChecks -Inventory $inventory -Net $net -AllowExternal $false
        $probed = Get-ProbedAddresses $net
        $probed.Count -gt 0 | Should Be $true
        foreach ($a in $probed) {
            $class = Get-AddressClass $a
            ($class -in 'private', 'linkLocal', 'loopback', 'uniqueLocal') | Should Be $true
        }
        $null -eq $data['external'] | Should Be $true
        $data['externalAllowed'] | Should Be $false
        $null -eq $data['externalConsentSource'] | Should Be $true
    }
    It 'records why a DNS server or proxy was not tested' {
        $data = Invoke-ConnectivityChecks -Inventory $inventory -Net (New-FakeNet) -AllowExternal $false
        ($data['dnsServers'] | ForEach-Object { $_['address'] + '=' + $_['reason'] }) -join ',' | Should Be '192.168.1.1=local,8.8.8.8=externalNotAllowed'
        ($data['proxies'] | ForEach-Object { $_['host'] + '=' + $_['reason'] + '/' + $_['tested'] }) -join ',' |
            Should Be '127.0.0.1=local/True,203.0.113.5=externalNotAllowed/False,proxy.example=externalNotAllowed/False,127.0.0.1=noPort/False'
    }
    It 'measures MTU for IPv4 gateways only and ties results to the route interface' {
        $data = Invoke-ConnectivityChecks -Inventory $inventory -Net (New-FakeNet) -AllowExternal $false
        $data['gateways'][0]['mtu']['mtu'] | Should Be 1500
        $null -eq $data['gateways'][1]['mtu'] | Should Be $true
        $data['gateways'][0]['viaInterfaceIndex'] | Should Be 3
        $data['dnsServers'][0]['viaInterfaceIndex'] | Should Be 7
        $data['context']['systemProxyEnabled'] | Should Be $true
        $data['context']['externalIPv4Via']['viaInterfaceAlias'] | Should Be 'Test'
    }
    It 'runs the external checks only with consent' {
        $net = New-FakeNet
        $data = Invoke-ConnectivityChecks -Inventory $inventory -Net $net -AllowExternal $true -ConsentSource 'cli'
        $data['externalConsentSource'] | Should Be 'cli'
        $e = $data['external']
        $e['ping'][0]['target'] | Should Be '198.51.100.1'
        $e['ping'][0]['viaInterfaceIndex'] | Should Be 7
        ($e['dns'][0]['results'] | ForEach-Object { $_['server'] + '/' + $_['source'] }) -join ',' | Should Be '198.51.100.53/config,192.168.1.1/interface,8.8.8.8/interface,system/system'
        $e['trace'][0]['status'] | Should Be 'reached'
        ($e['mtu'] | ForEach-Object { $_['target'] }) -join ',' | Should Be '198.51.100.1'
        ($data['dnsServers'] | Where-Object { $_['address'] -eq '8.8.8.8' })['tested'] | Should Be $true
    }
    It 'retries a lost external DNS answer instead of reporting the server as failed' {
        $state = @{ n = 0 }
        $net = New-FakeNet -Dns {
            param($s, $n, $t)
            if ($t -eq 1 -and $s -eq '198.51.100.53') { $state.n++; if ($state.n -eq 1) { return @{ status = 'timeout' } } }
            @{ status = 'answer'; rcode = 0; addresses = @('203.0.113.10'); rttMs = 5 }
        }.GetNewClosure()
        $data = Invoke-ConnectivityChecks -Inventory $inventory -Net $net -AllowExternal $true
        $first = $data['external']['dns'][0]['results'][0]
        $first['status'] | Should Be 'answer'
        $state.n | Should Be 2
        $data['external']['dns'][0]['failedServers'].Count | Should Be 0
    }
    It 'adds what the system resolver gives applications (hosts included)' {
        $net = New-FakeNet -System { param($n) @{ status = 'answer'; addresses = @('127.0.0.1'); rttMs = 1 } }
        $data = Invoke-ConnectivityChecks -Inventory $inventory -Net $net -AllowExternal $true
        $c = $data['external']['dns'][0]
        $c['results'][-1]['source'] | Should Be 'system'
        ($c['sinkholeServers'] -join ',') | Should Be 'system'
    }
    It 'never probes invalid targets from a targets file' {
        $bad = $inventory.Clone()
        $bad.targets = @{ ping = @('224.0.0.1'); dnsServers = @('255.255.255.255'); dnsNames = @('www.example.com'); trace = @('224.0.0.1'); mtu = @('0.0.0.0'); userFile = $true }
        $net = New-FakeNet
        $null = Invoke-ConnectivityChecks -Inventory $bad -Net $net -AllowExternal $true
        foreach ($a in (Get-ProbedAddresses $net)) { (Get-AddressClass $a) -in 'multicast', 'broadcast', 'unspecified' | Should Be $false }
    }
    It 'stops at the time budget and says so once' {
        $ctx = New-CollectorContext -Module 'connectivity' -Version '0'
        $budget = New-Budget -LimitMs 0
        $data = Invoke-ConnectivityChecks -Inventory $inventory -Net (New-FakeNet) -AllowExternal $true -Budget $budget -Context $ctx
        $data['gateways'][0]['ping']['reason'] | Should Be 'budget'
        $data['external']['trace'][0]['status'] | Should Be 'budget'
        @($ctx.Errors | Where-Object { $_['source'] -eq 'budget' }).Count | Should Be 1
        $ctx.Errors[0]['kind'] | Should Be 'Timeout'
    }
}

Describe 'connectivity: targets file' {
    . $collector

    It 'reads the built-in neutral targets' {
        $t = Read-ConnectivityTargets -BuiltInPath $TargetsFile -UserPath (Join-Path $TestDrive 'none.json')
        $t.ping.Count -gt 0 | Should Be $true
        $t.dnsNames.Count -gt 0 | Should Be $true
        $t.userFile | Should Be $false
    }
    It 'joins the user file and drops invalid entries with an error' {
        $user = Join-Path $TestDrive 'user.json'
        [IO.File]::WriteAllText($user, '{"ping":["198.51.100.9","not-an-ip"],"dns":{"names":["Example.ORG","bad name"]}}')
        $ctx = New-CollectorContext -Module 'connectivity' -Version '0'
        $t = Read-ConnectivityTargets -BuiltInPath $TargetsFile -UserPath $user -Context $ctx
        $t.userFile | Should Be $true
        $t.ping -contains '198.51.100.9' | Should Be $true
        $t.ping -contains 'not-an-ip' | Should Be $false
        $t.dnsNames -contains 'example.org' | Should Be $true
        $ctx.Errors.Count | Should Be 2
    }
    It 'ships only IP addresses and host names, ASCII-only' {
        @([IO.File]::ReadAllBytes($TargetsFile) | Where-Object { $_ -gt 127 }).Count | Should Be 0
        $ctx = New-CollectorContext -Module 'connectivity' -Version '0'
        $null = Read-ConnectivityTargets -BuiltInPath $TargetsFile -UserPath $null -Context $ctx
        $ctx.Errors.Count | Should Be 0
    }
}

Describe 'Collector: connectivity (local only)' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'connectivity.json')
    $data = $env['data']

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'connectivity') -join '; ' | Should Be ''
        $env['status'] | Should Match '^(ok|partial)$'
    }
    It 'runs no external checks without -AllowExternal' {
        $data['externalAllowed'] | Should Be $false
        $null -eq $data['external'] | Should Be $true
        foreach ($d in $data['dnsServers']) {
            if ($d['tested']) { $d['addressClass'] | Should Match '^(private|linkLocal|loopback|uniqueLocal)$' }
        }
        foreach ($p in $data['proxies']) {
            if ($p['tested']) { $p['addressClass'] | Should Match '^(private|linkLocal|loopback|uniqueLocal)$' }
        }
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'stays within the local time budget' {
        $env['durationMs'] -lt 30000 | Should Be $true
    }
}

Describe 'Collector: connectivity (external, owner only)' {
    if ($env:TUNNELEYE_TEST_EXTERNAL -ne '1') {
        It 'runs only with TUNNELEYE_TEST_EXTERNAL=1 (owner)' -Skip { }
        return
    }
    $out = Join-Path $TestDrive 'connectivity-external.json'
    & (Join-Path $PSHOME 'powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $collector -OutFile $out -AllowExternal | Out-Null
    $envelope = ConvertFrom-CollectorJson -Json ([IO.File]::ReadAllText($out, [Text.Encoding]::UTF8))

    It 'runs the external checks with explicit consent' {
        (Get-EnvelopeProblems -Envelope $envelope -Module 'connectivity') -join '; ' | Should Be ''
        $envelope['data']['externalAllowed'] | Should Be $true
        $envelope['data']['externalConsentSource'] | Should Be 'cli'
        $envelope['data']['external']['ping'].Count -gt 0 | Should Be $true
        $envelope['durationMs'] -lt 110000 | Should Be $true
    }
}
