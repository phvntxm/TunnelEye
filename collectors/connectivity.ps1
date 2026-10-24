# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'connectivity': connection tests (D-002). By default only the
# local segment is touched: echo requests and path MTU to the default
# gateways, a PTR query to DNS servers with private addresses, TCP connects
# to local proxies; Windows' own internet estimate (NCSI) is read, not
# probed. External tests (ping, DNS comparison, trace, path MTU to the
# targets of connectivity-targets.json) run only with -AllowExternal, given
# explicitly on each run. Every result records the interface the route goes
# through: ICMP, DNS and TCP bypass HTTP/SOCKS proxies, and some TUN stacks
# answer ICMP themselves.
# Schema: docs/schema/connectivity.md. No admin rights required.

param(
    [string] $OutFile,
    # Explicit consent to send probes outside the local network; never
    # enabled by a config file or a default.
    [switch] $AllowExternal,
    [ValidateSet('cli', 'gui')][string] $ConsentSource = 'cli'
)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

$TargetsFile = Join-Path $PSScriptRoot 'connectivity-targets.json'
$UserTargetsFile = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'TunnelEye\connectivity-targets.json' } else { $null }
$BudgetMs = 100000
$PingCount = 4
$PingTimeoutMs = 1000
$DnsTimeoutMs = 1500
$DnsAttempts = 2
$TcpTimeoutMs = 1000
$MtuBaselinePayload = 32
$MtuMaxPayload = 1472
$MtuAttempts = 3
$IPv4Overhead = 28
$TraceMaxHops = 30
$TraceStopAfterTimeouts = 5
# Windows' placeholders for interfaces without DNS (D-007): never probed.
$IgnoredDnsServers = 'fec0:0:0:ffff::1', 'fec0:0:0:ffff::2', 'fec0:0:0:ffff::3'
$LocalClasses = 'loopback', 'private', 'linkLocal', 'uniqueLocal'
# Route lookups for the externalIPv4/IPv6 context: documentation addresses
# (RFC 5737, RFC 3849), as in 'routing'. Find-NetRoute sends no packets.
$ContextTargets = @{ ipv4 = '192.0.2.1'; ipv6 = '2001:db8::1' }

# --- Targets and addresses ---------------------------------------------------

function Test-TargetAllowed {
    # The single place that decides whether a target may be probed. Local:
    # loopback, private (RFC 1918, fec0::/10), link-local, unique local.
    # Gateways are always local (on-link next hop, D-002). Everything else
    # (public, CGNAT) needs -AllowExternal. Hostnames are not resolved to
    # classify them: only 'localhost' counts as local.
    param($Address, [bool] $AllowExternal, [switch] $Gateway)
    if ($Gateway) { return @{ allowed = $true; addressClass = (Get-AddressClass $Address); reason = 'gateway' } }
    $class = Get-AddressClass $Address
    if ($null -eq $class) {
        if ([string]$Address -eq 'localhost') { return @{ allowed = $true; addressClass = 'loopback'; reason = 'local' } }
        return @{ allowed = $AllowExternal; addressClass = $null; reason = if ($AllowExternal) { 'external' } else { 'externalNotAllowed' } }
    }
    if ($class -in 'unspecified', 'multicast', 'broadcast') { return @{ allowed = $false; addressClass = $class; reason = 'invalidTarget' } }
    if ($LocalClasses -contains $class) { return @{ allowed = $true; addressClass = $class; reason = 'local' } }
    @{ allowed = $AllowExternal; addressClass = $class; reason = if ($AllowExternal) { 'external' } else { 'externalNotAllowed' } }
}

function Get-ReverseName {
    # PTR name of an address: 1.1.168.192.in-addr.arpa, or nibbles for IPv6.
    param([Parameter(Mandatory)][string] $Address)
    $ip = [System.Net.IPAddress]::Parse(($Address -replace '%.*$', ''))
    $bytes = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        [array]::Reverse($bytes)
        return (($bytes | ForEach-Object { [string]$_ }) -join '.') + '.in-addr.arpa'
    }
    $nibbles = foreach ($b in $bytes) { '{0:x}' -f ($b -shr 4); '{0:x}' -f ($b -band 0xF) }
    [array]::Reverse($nibbles)
    ($nibbles -join '.') + '.ip6.arpa'
}

function ConvertFrom-ProxyString {
    # ProxyServer values: "host:port", "http=host:port;https=host:port",
    # "http://host:port", "socks=host:port", "[::1]:8080". Credentials are
    # stripped first. Returns @{ scheme; host; port } (port $null if absent).
    param($Value)
    $clean = (Remove-UrlCredential $Value).value
    if ($null -eq $clean) { return , @() }
    , @(foreach ($part in ($clean -split ';')) {
            $p = $part.Trim()
            if ($p -eq '') { continue }
            $scheme = $null
            if ($p -match '^([A-Za-z]+)=(.*)$') { $scheme = $Matches[1].ToLowerInvariant(); $p = $Matches[2].Trim() }
            if ($p -match '^([A-Za-z][A-Za-z0-9+.-]*)://(.*)$') {
                if ($null -eq $scheme) { $scheme = $Matches[1].ToLowerInvariant() }
                $p = $Matches[2]
            }
            $p = $p.TrimEnd('/')
            $hostPart = $null
            $port = $null
            if ($p -match '^\[([^\]]+)\](?::(\d+))?$') { $hostPart = $Matches[1]; if ($Matches[2]) { $port = [int]$Matches[2] } }
            elseif ($p -match '^([^:]+):(\d+)$') { $hostPart = $Matches[1]; $port = [int]$Matches[2] }
            elseif ($p -notmatch ':') { $hostPart = $p }
            if ($hostPart) { @{ scheme = $scheme; host = $hostPart; port = $port } }
        })
}

function Read-ConnectivityTargets {
    # Built-in targets plus the user's own file, if present: lists are joined
    # without duplicates. Ping/trace/MTU targets and DNS servers must be IP
    # literals (no name resolution to find a target); DNS names must look
    # like host names. Invalid entries are reported and dropped.
    param([string] $BuiltInPath, [string] $UserPath, $Context)
    $merged = @{ ping = @(); dnsServers = @(); dnsNames = @(); trace = @(); mtu = @() }
    $userFile = $false
    foreach ($path in @($BuiltInPath, $UserPath)) {
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { continue }
        if ($path -eq $UserPath) { $userFile = $true }
        $doc = ConvertFrom-CollectorJson -Json ([IO.File]::ReadAllText($path, [Text.Encoding]::UTF8))
        # JSON objects come as Dictionary[string,object]: ContainsKey, not Contains.
        $get = { param($d, $k) if ($d -is [System.Collections.IDictionary] -and $d.ContainsKey($k)) { @($d[$k]) } else { @() } }
        $dns = @{}
        if ($doc -is [System.Collections.IDictionary] -and $doc.ContainsKey('dns')) { $dns = $doc['dns'] }
        $merged.ping += & $get $doc 'ping'
        $merged.trace += & $get $doc 'trace'
        $merged.mtu += & $get $doc 'mtu'
        $merged.dnsServers += & $get $dns 'servers'
        $merged.dnsNames += & $get $dns 'names'
    }
    $ip = [System.Net.IPAddress]::None
    foreach ($key in 'ping', 'trace', 'mtu', 'dnsServers') {
        $valid = @(foreach ($v in $merged[$key]) {
                if ([System.Net.IPAddress]::TryParse([string]$v, [ref]$ip)) { [string]$v }
                elseif ($null -ne $Context) { Add-CollectorError -Context $Context -Source 'connectivity-targets.json' -Kind Exception -Message "Not an IP address in '$key': $v" }
            })
        $merged[$key] = @($valid | Select-Object -Unique)
    }
    $names = @(foreach ($n in $merged.dnsNames) {
            if ([string]$n -match '^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$') { ([string]$n).ToLowerInvariant() }
            elseif ($null -ne $Context) { Add-CollectorError -Context $Context -Source 'connectivity-targets.json' -Kind Exception -Message "Not a host name in 'dns.names': $n" }
        })
    $merged.dnsNames = @($names | Select-Object -Unique)
    $merged.userFile = $userFile
    $merged
}

# --- DNS wire format ---------------------------------------------------------
# A minimal DNS client: Resolve-DnsName waits about 7 s for a silent server
# even with -QuickTimeout, and its errors are localized text.

function New-DnsQuery {
    # Query packet: header with RD set, one question of the given type (1 A,
    # 28 AAAA, 12 PTR), class IN.
    param([Parameter(Mandatory)][string] $Name, [int] $Type = 1, [int] $Id = 0)
    $ms = New-Object IO.MemoryStream
    # Bytes computed one by one: in an array literal the comma binds tighter
    # than -band.
    $idHigh = [byte](($Id -shr 8) -band 0xFF)
    $idLow = [byte]($Id -band 0xFF)
    $typeHigh = [byte](($Type -shr 8) -band 0xFF)
    $typeLow = [byte]($Type -band 0xFF)
    $header = [byte[]]@($idHigh, $idLow, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
    $ms.Write($header, 0, $header.Length)
    foreach ($label in ($Name.TrimEnd('.') -split '\.')) {
        $bytes = [Text.Encoding]::ASCII.GetBytes($label)
        $ms.WriteByte([byte]$bytes.Length)
        $ms.Write($bytes, 0, $bytes.Length)
    }
    $tail = [byte[]]@(0, $typeHigh, $typeLow, 0, 1)
    $ms.Write($tail, 0, $tail.Length)
    , $ms.ToArray()
}

function Skip-DnsName {
    # Offset after a (possibly compressed) name starting at $Offset.
    param([byte[]] $Bytes, [int] $Offset)
    while ($Offset -lt $Bytes.Length) {
        $len = $Bytes[$Offset]
        if (($len -band 0xC0) -eq 0xC0) { return $Offset + 2 }
        if ($len -eq 0) { return $Offset + 1 }
        $Offset += 1 + $len
    }
    -1
}

function ConvertFrom-DnsResponse {
    # Parses a response: @{ rcode; truncated; addresses } with A and AAAA
    # answers, or $null if it is not a response to query $Id.
    param([byte[]] $Bytes, [int] $Id)
    if ($null -eq $Bytes -or $Bytes.Length -lt 12) { return $null }
    if ((([int]$Bytes[0] -shl 8) -bor $Bytes[1]) -ne $Id) { return $null }
    if (($Bytes[2] -band 0x80) -eq 0) { return $null }
    $rcode = $Bytes[3] -band 0x0F
    $qd = ([int]$Bytes[4] -shl 8) -bor $Bytes[5]
    $an = ([int]$Bytes[6] -shl 8) -bor $Bytes[7]
    $offset = 12
    for ($i = 0; $i -lt $qd -and $offset -ge 0; $i++) { $offset = Skip-DnsName $Bytes $offset; if ($offset -ge 0) { $offset += 4 } }
    $addresses = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $an -and $offset -ge 0 -and $offset -lt $Bytes.Length; $i++) {
        $offset = Skip-DnsName $Bytes $offset
        if ($offset -lt 0 -or $offset + 10 -gt $Bytes.Length) { break }
        $type = ([int]$Bytes[$offset] -shl 8) -bor $Bytes[$offset + 1]
        $rdLength = ([int]$Bytes[$offset + 8] -shl 8) -bor $Bytes[$offset + 9]
        $data = $offset + 10
        if ($data + $rdLength -gt $Bytes.Length) { break }
        if (($type -eq 1 -and $rdLength -eq 4) -or ($type -eq 28 -and $rdLength -eq 16)) {
            $raw = New-Object byte[] $rdLength
            [Array]::Copy($Bytes, $data, $raw, 0, $rdLength)
            $addresses.Add(([System.Net.IPAddress]::new($raw)).ToString())
        }
        $offset = $data + $rdLength
    }
    @{ rcode = [int]$rcode; truncated = (($Bytes[2] -band 0x02) -ne 0); addresses = $addresses.ToArray() }
}

function ConvertTo-DnsStatus {
    # Response -> status: answer (NOERROR), nxdomain, or rcode (SERVFAIL,
    # REFUSED, ...). Any of them means the server answered.
    param($Response)
    if ($null -eq $Response) { return 'timeout' }
    switch ($Response.rcode) { 0 { 'answer' } 3 { 'nxdomain' } default { 'rcode' } }
}

# --- Probes on injected network functions -------------------------------------
# $Net: @{ ping = { param($Address, $Size, $Ttl, $DontFragment, $TimeoutMs) }
#          dns  = { param($Server, $Name, $Type, $TimeoutMs) }
#          tcp  = { param($Host, $Port, $TimeoutMs) }
#          route = { param($Address) } }
# ping -> @{ status; rttMs; address }, dns -> @{ status; rcode; addresses;
# rttMs }, tcp -> @{ status } (open | refused | timeout | error),
# route -> @{ interfaceIndex; interfaceAlias } or $null.

function New-Budget {
    param([int] $LimitMs)
    [pscustomobject]@{ Watch = [Diagnostics.Stopwatch]::StartNew(); LimitMs = $LimitMs; Exceeded = $false }
}

function Test-Budget {
    # True while time is left; once exceeded, stays exceeded.
    param($Budget)
    if ($null -eq $Budget) { return $true }
    if (-not $Budget.Exceeded -and $Budget.Watch.ElapsedMilliseconds -ge $Budget.LimitMs) { $Budget.Exceeded = $true }
    -not $Budget.Exceeded
}

function Invoke-PingSeries {
    param([string] $Address, $Net, [int] $Count = 4, [int] $TimeoutMs = 1000)
    $rtts = [System.Collections.Generic.List[int64]]::new()
    $statuses = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Count; $i++) {
        $r = & $Net.ping $Address 32 128 $false $TimeoutMs
        $statuses.Add([string]$r.status)
        if ($r.status -eq 'Success') { $rtts.Add([int64]$r.rttMs) }
    }
    $failure = @($statuses | Where-Object { $_ -ne 'Success' } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1)
    [ordered]@{
        sent        = $Count
        received    = $rtts.Count
        lossPercent = [int][math]::Round(100 * ($Count - $rtts.Count) / [math]::Max(1, $Count))
        rttMinMs    = if ($rtts.Count) { ($rtts | Measure-Object -Minimum).Minimum } else { $null }
        rttAvgMs    = if ($rtts.Count) { [math]::Round(($rtts | Measure-Object -Average).Average, 1) } else { $null }
        rttMaxMs    = if ($rtts.Count) { ($rtts | Measure-Object -Maximum).Maximum } else { $null }
        status      = if ($rtts.Count) { 'Success' } elseif ($failure.Count) { $failure[0].Name } else { 'Error' }
    }
}

function Find-PathMtu {
    # Largest echo payload that passes with Don't Fragment (IPv4 only).
    # A lost reply is not "too big": TimedOut is retried ($Attempts in all)
    # before a size counts as not passing; PacketTooBig fails at once. No
    # reply to a small baseline echo -> no search at all (noEchoReply).
    # The search is binary between the baseline and $MaxPayload (1472 =
    # 1500 - 28); the first probe tries $MaxPayload, the common case.
    param([string] $Address, $Net, [int] $TimeoutMs = 1000, [int] $Attempts = 3, [int] $Baseline = 32, [int] $MaxPayload = 1472)
    $state = @{ probes = 0; timeoutsCountedAsFail = 0 }
    $probe = {
        param([int] $Size)
        for ($a = 1; $a -le $Attempts; $a++) {
            $state.probes++
            $r = & $Net.ping $Address $Size 128 $true $TimeoutMs
            if ($r.status -eq 'Success') { return $true }
            if ($r.status -ne 'TimedOut') { return $false }
        }
        $state.timeoutsCountedAsFail++
        $false
    }
    if (-not (& $probe $Baseline)) {
        return [ordered]@{ maxPayload = $null; mtu = $null; status = 'noEchoReply'; probes = $state.probes; timeoutsCountedAsFail = 0 }
    }
    $good = $Baseline
    $bad = $MaxPayload + 1
    if (& $probe $MaxPayload) { $good = $MaxPayload }
    else {
        $bad = $MaxPayload
        while ($bad - $good -gt 1) {
            $mid = [int][math]::Floor(($good + $bad) / 2)
            if (& $probe $mid) { $good = $mid } else { $bad = $mid }
        }
    }
    [ordered]@{
        maxPayload            = $good
        mtu                   = $good + $IPv4Overhead
        status                = 'ok'
        probes                = $state.probes
        timeoutsCountedAsFail = $state.timeoutsCountedAsFail
    }
}

function Invoke-Trace {
    # Echo requests with growing TTL, one per hop. Stops at the target, at an
    # error other than TimedOut, after $StopAfterTimeouts timeouts in a row
    # (ICMP is often dropped past some hop) or at $MaxHops.
    param([string] $Address, $Net, [int] $MaxHops = 30, [int] $StopAfterTimeouts = 5, [int] $TimeoutMs = 1000, $Budget)
    $hops = [System.Collections.Generic.List[object]]::new()
    $status = 'maxHops'
    $silent = 0
    for ($ttl = 1; $ttl -le $MaxHops; $ttl++) {
        if (-not (Test-Budget $Budget)) { $status = 'budget'; break }
        $r = & $Net.ping $Address 32 $ttl $false $TimeoutMs
        $s = [string]$r.status
        # Values first: inside .Add(...) a comma would split method arguments.
        $hopAddress = $null
        if ($s -ne 'TimedOut') { $hopAddress = $r.address }
        # .NET reports RoundtripTime only for Success; for TtlExpired it is
        # always 0, which would read as a 0 ms hop.
        $hopRtt = $null
        if ($s -eq 'Success') { $hopRtt = $r.rttMs }
        $hop = [ordered]@{ ttl = $ttl; address = $hopAddress; rttMs = $hopRtt; status = $s }
        $hops.Add($hop)
        if ($s -eq 'Success') { $status = 'reached'; break }
        if ($s -eq 'TimedOut') {
            $silent++
            if ($silent -ge $StopAfterTimeouts) { $status = 'stoppedAfterTimeouts'; break }
            continue
        }
        $silent = 0
        if ($s -ne 'TtlExpired') { $status = 'unreachable'; break }
    }
    [ordered]@{ status = $status; hops = $hops.ToArray() }
}

function Test-DnsServer {
    # Liveness of a DNS server: a PTR query for the server's own address.
    # Any answer, NXDOMAIN included, means it responds; private reverse zones
    # are mostly answered by the server itself (RFC 6303). TCP 53 is not a
    # sign: many home routers do not listen on it.
    param([string] $Address, $Net, [int] $TimeoutMs = 1500, [int] $Attempts = 2)
    $name = Get-ReverseName $Address
    $r = $null
    for ($a = 1; $a -le $Attempts; $a++) {
        $r = & $Net.dns $Address $name 12 $TimeoutMs
        if ($r.status -ne 'timeout') { break }
    }
    [ordered]@{
        responds = ($r.status -in 'answer', 'nxdomain', 'rcode')
        status   = $r.status
        rcode    = $r.rcode
        rttMs    = $r.rttMs
    }
}

function Compare-DnsAnswers {
    # Facts for the "DNS spoofing" rule: which servers answered what. Sinkhole
    # answers are unspecified or loopback addresses (0.0.0.0, 127.x, ::);
    # distinctAnswerSets counts different address sets among the answers
    # (CDNs legitimately return different addresses, the analyzer weighs it).
    param([string] $Name, [object[]] $Results)
    $sets = @{}
    foreach ($r in $Results) {
        if ($r['status'] -eq 'answer' -and @($r['addresses']).Count) { $sets[(@($r['addresses'] | Sort-Object) -join ',')] = $true }
    }
    [ordered]@{
        name               = $Name
        results            = $Results
        distinctAnswerSets = $sets.Count
        sinkholeServers    = @($Results | Where-Object { @($_['addresses'] | Where-Object { (Get-AddressClass $_) -in 'unspecified', 'loopback' }).Count } | ForEach-Object { $_['server'] })
        nxdomainServers    = @($Results | Where-Object { $_['status'] -eq 'nxdomain' } | ForEach-Object { $_['server'] })
        failedServers      = @($Results | Where-Object { $_['status'] -in 'timeout', 'error' } | ForEach-Object { $_['server'] })
    }
}

function Get-Via {
    # Interface the route to $Address goes through, from the route table.
    param([string] $Address, $Net)
    $v = & $Net.route $Address
    if ($null -eq $v) { return @{ viaInterfaceIndex = $null; viaInterfaceAlias = $null } }
    @{ viaInterfaceIndex = $v.interfaceIndex; viaInterfaceAlias = $v.interfaceAlias }
}

function Invoke-ConnectivityChecks {
    # Runs all checks on an inventory gathered by the collector:
    # @{ profiles; systemProxyEnabled; gateways[{ address; family;
    #    interfaceIndex; interfaceAlias }]; dnsServers[{ address;
    #    interfaceIndex }]; proxies[{ source; enabled; scheme; host; port }];
    #    targets (only with -AllowExternal) }.
    # Every probe target passes Test-TargetAllowed; without -AllowExternal no
    # public address is probed (covered by tests).
    param(
        [Parameter(Mandatory)][hashtable] $Inventory,
        [Parameter(Mandatory)] $Net,
        [bool] $AllowExternal,
        [string] $ConsentSource = 'cli',
        $Budget,
        $Context
    )
    # Dot-sourced where a check is skipped for lack of time: one error per run.
    $budgetNoted = $false
    $skippedBudget = {
        if (-not $budgetNoted -and $null -ne $Context) {
            Add-CollectorError -Context $Context -Source 'budget' -Kind Timeout -Message "Connectivity checks stopped after $($Budget.LimitMs) ms; the remaining checks are skipped."
        }
        $budgetNoted = $true
    }

    # Not $context: PowerShell names are case-insensitive, it would replace
    # the $Context parameter that collects the errors.
    $pathContext = [ordered]@{
        systemProxyEnabled = $Inventory.systemProxyEnabled
        externalIPv4Via    = Get-Via $ContextTargets.ipv4 $Net
        externalIPv6Via    = Get-Via $ContextTargets.ipv6 $Net
    }

    $gateways = @(foreach ($g in @($Inventory.gateways)) {
            if ($null -eq $g) { continue }
            $entry = [ordered]@{
                address           = $g.address
                family            = $g.family
                interfaceIndex    = $g.interfaceIndex
                interfaceAlias    = $g.interfaceAlias
                viaInterfaceIndex = $g.interfaceIndex
                viaInterfaceAlias = $g.interfaceAlias
                ping              = $null
                mtu               = $null
            }
            if (-not (Test-Budget $Budget)) { . $skippedBudget; $entry.ping = @{ status = 'skipped'; reason = 'budget' }; $entry; continue }
            $entry.ping = Invoke-PingSeries -Address $g.address -Net $Net -Count $PingCount -TimeoutMs $PingTimeoutMs
            if ($g.family -eq 'IPv4' -and $entry.ping.received -gt 0 -and (Test-Budget $Budget)) {
                $entry.mtu = Find-PathMtu -Address $g.address -Net $Net -TimeoutMs $PingTimeoutMs -Attempts $MtuAttempts -Baseline $MtuBaselinePayload -MaxPayload $MtuMaxPayload
            }
            $entry
        })

    $seen = @{}
    $dnsServers = @(foreach ($d in @($Inventory.dnsServers)) {
            if ($null -eq $d) { continue }
            $bare = ([string]$d.address -replace '%.*$', '').ToLowerInvariant()
            if ($IgnoredDnsServers -contains $bare -or $seen.ContainsKey([string]$d.address)) { continue }
            $seen[[string]$d.address] = $true
            $allowed = Test-TargetAllowed -Address $bare -AllowExternal $AllowExternal
            $entry = [ordered]@{
                address           = $d.address
                interfaceIndex    = $d.interfaceIndex
                addressClass      = $allowed.addressClass
                tested            = $false
                reason            = $allowed.reason
                responds          = $null
                status            = $null
                rcode             = $null
                rttMs             = $null
                viaInterfaceIndex = $null
                viaInterfaceAlias = $null
            }
            if ($allowed.allowed -and -not (Test-Budget $Budget)) { . $skippedBudget; $entry.reason = 'budget' }
            elseif ($allowed.allowed) {
                $result = Test-DnsServer -Address $d.address -Net $Net -TimeoutMs $DnsTimeoutMs -Attempts $DnsAttempts
                $entry.tested = $true
                $entry.responds = $result.responds
                $entry.status = $result.status
                $entry.rcode = $result.rcode
                $entry.rttMs = $result.rttMs
                $via = Get-Via $bare $Net
                $entry.viaInterfaceIndex = $via.viaInterfaceIndex
                $entry.viaInterfaceAlias = $via.viaInterfaceAlias
            }
            $entry
        })

    $proxies = @(foreach ($p in @($Inventory.proxies)) {
            if ($null -eq $p) { continue }
            $allowed = Test-TargetAllowed -Address $p.host -AllowExternal $AllowExternal
            $entry = [ordered]@{
                source            = $p.source
                enabled           = $p.enabled
                scheme            = $p.scheme
                host              = $p.host
                port              = $p.port
                addressClass      = $allowed.addressClass
                tested            = $false
                reason            = $allowed.reason
                status            = $null
                viaInterfaceIndex = $null
                viaInterfaceAlias = $null
            }
            if ($null -eq $p.port) { $entry.reason = 'noPort' }
            elseif ($allowed.allowed -and -not (Test-Budget $Budget)) { . $skippedBudget; $entry.reason = 'budget' }
            elseif ($allowed.allowed) {
                $entry.tested = $true
                $entry.status = (& $Net.tcp $p.host $p.port $TcpTimeoutMs).status
                if ($null -ne (Get-AddressClass $p.host)) {
                    $via = Get-Via $p.host $Net
                    $entry.viaInterfaceIndex = $via.viaInterfaceIndex
                    $entry.viaInterfaceAlias = $via.viaInterfaceAlias
                }
            }
            $entry
        })

    $external = $null
    if ($AllowExternal) {
        $t = $Inventory.targets
        $ping = @(foreach ($a in @($t.ping)) {
                if (-not (Test-TargetAllowed -Address $a -AllowExternal $true).allowed) { continue }
                $via = Get-Via $a $Net
                $entry = [ordered]@{ target = $a; viaInterfaceIndex = $via.viaInterfaceIndex; viaInterfaceAlias = $via.viaInterfaceAlias; result = $null }
                if (Test-Budget $Budget) { $entry.result = Invoke-PingSeries -Address $a -Net $Net -Count $PingCount -TimeoutMs $PingTimeoutMs }
                else { . $skippedBudget; $entry.result = @{ status = 'skipped'; reason = 'budget' } }
                $entry
            })

        # Servers: from the config and from the interfaces (public ones too:
        # consent is given). Same server listed twice is asked once.
        $servers = [System.Collections.Generic.List[object]]::new()
        $known = @{}
        foreach ($s in @($t.dnsServers)) {
            if (-not (Test-TargetAllowed -Address $s -AllowExternal $true).allowed) { continue }
            if (-not $known.ContainsKey($s)) { $known[$s] = $true; $servers.Add(@{ server = $s; source = 'config' }) }
        }
        foreach ($d in $dnsServers) { $a = [string]$d.address; if ($d.addressClass -notin 'unspecified', 'multicast', 'broadcast' -and -not $known.ContainsKey($a)) { $known[$a] = $true; $servers.Add(@{ server = $a; source = 'interface' }) } }
        $dns = @(foreach ($name in @($t.dnsNames)) {
                $results = @(foreach ($s in $servers) {
                        if (-not (Test-Budget $Budget)) { . $skippedBudget; [ordered]@{ server = $s.server; source = $s.source; status = 'skipped'; rcode = $null; addresses = @(); rttMs = $null }; continue }
                        $r = & $Net.dns $s.server $name 1 $DnsTimeoutMs
                        [ordered]@{ server = $s.server; source = $s.source; status = $r.status; rcode = $r.rcode; addresses = @($r.addresses); rttMs = $r.rttMs }
                    })
                Compare-DnsAnswers -Name $name -Results $results
            })

        $trace = @(foreach ($a in @($t.trace)) {
                if (-not (Test-TargetAllowed -Address $a -AllowExternal $true).allowed) { continue }
                $via = Get-Via $a $Net
                $r = Invoke-Trace -Address $a -Net $Net -MaxHops $TraceMaxHops -StopAfterTimeouts $TraceStopAfterTimeouts -TimeoutMs $PingTimeoutMs -Budget $Budget
                if ($r.status -eq 'budget') { . $skippedBudget }
                [ordered]@{ target = $a; viaInterfaceIndex = $via.viaInterfaceIndex; viaInterfaceAlias = $via.viaInterfaceAlias; status = $r.status; hops = $r.hops }
            })

        $mtu = @(foreach ($a in @($t.mtu)) {
                if ((Get-AddressClass $a) -ne 'public' -or $a -match ':') { continue }
                $via = Get-Via $a $Net
                $entry = [ordered]@{ target = $a; viaInterfaceIndex = $via.viaInterfaceIndex; viaInterfaceAlias = $via.viaInterfaceAlias; result = $null }
                if (Test-Budget $Budget) { $entry.result = Find-PathMtu -Address $a -Net $Net -TimeoutMs $PingTimeoutMs -Attempts $MtuAttempts -Baseline $MtuBaselinePayload -MaxPayload $MtuMaxPayload }
                else { . $skippedBudget; $entry.result = @{ status = 'skipped'; reason = 'budget' } }
                $entry
            })

        $external = [ordered]@{
            userTargetsFile = [bool]$t.userFile
            ping            = $ping
            dns             = $dns
            trace           = $trace
            mtu             = $mtu
        }
    }

    [ordered]@{
        externalAllowed       = $AllowExternal
        externalConsentSource = if ($AllowExternal) { $ConsentSource } else { $null }
        windowsConnectivity   = $Inventory.profiles
        context               = $pathContext
        gateways              = $gateways
        dnsServers            = $dnsServers
        proxies               = $proxies
        external              = $external
    }
}

# --- Real network functions --------------------------------------------------

$RealNet = @{
    ping  = {
        param($Address, $Size, $Ttl, $DontFragment, $TimeoutMs)
        $p = New-Object System.Net.NetworkInformation.Ping
        try {
            $ip = [System.Net.IPAddress]::Parse([string]$Address)
            # Don't Fragment applies to IPv4 only.
            $df = [bool]$DontFragment -and $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
            $options = New-Object System.Net.NetworkInformation.PingOptions([int]$Ttl, $df)
            $reply = $p.Send($ip, [int]$TimeoutMs, (New-Object byte[] ([int]$Size)), $options)
            @{ status = [string]$reply.Status; rttMs = [int64]$reply.RoundtripTime; address = if ($null -ne $reply.Address -and -not $reply.Address.Equals([System.Net.IPAddress]::Any) -and -not $reply.Address.Equals([System.Net.IPAddress]::IPv6Any)) { $reply.Address.ToString() } else { $null } }
        }
        catch { @{ status = 'Error'; rttMs = $null; address = $null } }
        finally { $p.Dispose() }
    }
    dns   = {
        param($Server, $Name, $Type, $TimeoutMs)
        $id = Get-Random -Minimum 1 -Maximum 65535
        $client = $null
        $watch = [Diagnostics.Stopwatch]::StartNew()
        try {
            $ip = [System.Net.IPAddress]::Parse([string]$Server)
            $client = New-Object System.Net.Sockets.UdpClient($ip.AddressFamily)
            $client.Client.ReceiveTimeout = [int]$TimeoutMs
            $packet = New-DnsQuery -Name $Name -Type $Type -Id $id
            $endpoint = New-Object System.Net.IPEndPoint($ip, 53)
            [void]$client.Send($packet, $packet.Length, $endpoint)
            $from = New-Object System.Net.IPEndPoint($ip, 0)
            while ($true) {
                $bytes = $client.Receive([ref]$from)
                $response = ConvertFrom-DnsResponse -Bytes $bytes -Id $id
                if ($null -ne $response) {
                    return @{ status = ConvertTo-DnsStatus $response; rcode = $response.rcode; addresses = $response.addresses; rttMs = $watch.ElapsedMilliseconds }
                }
                if ($watch.ElapsedMilliseconds -ge $TimeoutMs) { break }
            }
            @{ status = 'timeout'; rcode = $null; addresses = @(); rttMs = $null }
        }
        catch [System.Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) { return @{ status = 'timeout'; rcode = $null; addresses = @(); rttMs = $null } }
            @{ status = 'error'; rcode = $null; addresses = @(); rttMs = $null }
        }
        catch { @{ status = 'error'; rcode = $null; addresses = @(); rttMs = $null } }
        finally { if ($null -ne $client) { $client.Close() } }
    }
    tcp   = {
        param($HostName, $Port, $TimeoutMs)
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $task = $client.ConnectAsync([string]$HostName, [int]$Port)
            if (-not $task.Wait([int]$TimeoutMs)) { return @{ status = 'timeout' } }
            @{ status = 'open' }
        }
        catch {
            $inner = $_.Exception
            while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
            if ($inner -is [System.Net.Sockets.SocketException] -and $inner.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) { return @{ status = 'refused' } }
            @{ status = 'error' }
        }
        finally { $client.Close() }
    }
    route = {
        param($Address)
        try {
            $found = @(Find-NetRoute -RemoteIPAddress ([string]$Address -replace '%.*$', '') -ErrorAction Stop | Where-Object { $_.InterfaceAlias } | Select-Object -First 1)
            if ($found.Count) { return @{ interfaceIndex = [int]$found[0].InterfaceIndex; interfaceAlias = $found[0].InterfaceAlias } }
        }
        catch { }
        $null
    }
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'connectivity' -Version '1.0.1' -OutFile $OutFile -ScriptBlock {
    param($ctx)
    $budget = New-Budget -LimitMs $BudgetMs

    # Windows' own estimate (NCSI): read, not probed. The network name (SSID
    # for Wi-Fi) is not collected here.
    $profiles = Invoke-Source -Context $ctx -Source 'Get-NetConnectionProfile' -AsList -ScriptBlock {
        Invoke-AllowNotFound { Get-NetConnectionProfile -ErrorAction Stop } | Sort-Object InterfaceIndex | ForEach-Object {
            [ordered]@{
                interfaceIndex  = [int]$_.InterfaceIndex
                interfaceAlias  = $_.InterfaceAlias
                networkCategory = [string]$_.NetworkCategory
                ipv4            = [string]$_.IPv4Connectivity
                ipv6            = [string]$_.IPv6Connectivity
            }
        }
    }

    $up = @{}
    $adapters = Invoke-Source -Context $ctx -Source 'Get-NetAdapter' -AsList -ScriptBlock {
        Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { [int]$_.InterfaceIndex }
    }
    foreach ($i in @($adapters)) { if ($null -ne $i) { $up[$i] = $true } }

    $gateways = Invoke-Source -Context $ctx -Source 'Get-NetRoute' -AsList -ScriptBlock {
        $seen = @{}
        # Each prefix on its own: a missing ::/0 is "not found", not an error,
        # and must not drop the IPv4 gateways.
        $routes = @(foreach ($prefix in '0.0.0.0/0', '::/0') { Invoke-AllowNotFound { Get-NetRoute -DestinationPrefix $prefix -ErrorAction Stop } })
        foreach ($r in $routes) {
            if ($r.NextHop -in '0.0.0.0', '::') { continue }
            $family = if ($r.DestinationPrefix -eq '0.0.0.0/0') { 'IPv4' } else { 'IPv6' }
            # Link-local next hops need the interface as zone.
            $address = if ($family -eq 'IPv6' -and $r.NextHop -like 'fe80:*') { '{0}%{1}' -f $r.NextHop, $r.InterfaceIndex } else { $r.NextHop }
            if ($seen.ContainsKey($address)) { continue }
            $seen[$address] = $true
            @{ address = $address; family = $family; interfaceIndex = [int]$r.InterfaceIndex; interfaceAlias = $r.InterfaceAlias }
        }
    }

    $dnsServers = Invoke-Source -Context $ctx -Source 'Get-DnsClientServerAddress' -AsList -ScriptBlock {
        foreach ($s in (Get-DnsClientServerAddress -ErrorAction Stop)) {
            if ($up.Count -and -not $up.ContainsKey([int]$s.InterfaceIndex)) { continue }
            foreach ($a in @($s.ServerAddresses)) {
                if (-not $a) { continue }
                $address = if ($a -like 'fe80:*' -and $a -notmatch '%') { '{0}%{1}' -f $a, $s.InterfaceIndex } else { $a }
                @{ address = $address; interfaceIndex = [int]$s.InterfaceIndex }
            }
        }
    }

    # Proxy settings are read again here (the modules are independent of
    # each other): user and machine Internet Settings, and WinHTTP.
    $systemProxyEnabled = $null

    try {
        $enable = Get-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'ProxyEnable'
        $systemProxyEnabled = ($null -ne $enable -and [int]$enable -eq 1)
    }
    catch { Add-CollectorError -Context $ctx -Source 'ProxyEnable' -Kind (Get-ErrorKind $_) -Message $_.Exception.Message }
    $proxies = Invoke-Source -Context $ctx -Source 'proxy settings' -AsList -ScriptBlock {
        foreach ($k in @(
                @{ source = 'user'; path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' }
                @{ source = 'machine'; path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' })) {
            $server = Get-RegistryValue -Path $k.path -Name 'ProxyServer'
            $enable = Get-RegistryValue -Path $k.path -Name 'ProxyEnable'

            foreach ($p in (ConvertFrom-ProxyString $server)) {
                @{ source = $k.source; enabled = ($null -ne $enable -and [int]$enable -eq 1); scheme = $p.scheme; host = $p.host; port = $p.port }
            }
        }
        $blob = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Name 'WinHttpSettings'
        $winhttp = ConvertFrom-ConnectionSettingsBlob $blob
        if ($null -ne $winhttp -and $winhttp.proxyServer) {
            foreach ($p in (ConvertFrom-ProxyString $winhttp.proxyServer)) {
                @{ source = 'winhttp'; enabled = [bool]$winhttp.proxyEnabled; scheme = $p.scheme; host = $p.host; port = $p.port }
            }
        }
    }

    $targets = $null
    if ($AllowExternal) {
        $targets = Invoke-Source -Context $ctx -Source 'connectivity-targets.json' -ScriptBlock {
            Read-ConnectivityTargets -BuiltInPath $TargetsFile -UserPath $UserTargetsFile -Context $ctx
        }
        if ($null -eq $targets) { $targets = @{ ping = @(); dnsServers = @(); dnsNames = @(); trace = @(); mtu = @(); userFile = $false } }
    }

    $inventory = @{
        profiles           = $profiles
        systemProxyEnabled = $systemProxyEnabled
        gateways           = @($gateways | Where-Object { $null -ne $_ })
        dnsServers         = @($dnsServers | Where-Object { $null -ne $_ })
        proxies            = @($proxies | Where-Object { $null -ne $_ })
        targets            = $targets
    }
    Invoke-ConnectivityChecks -Inventory $inventory -Net $RealNet -AllowExternal ([bool]$AllowExternal) -ConsentSource $ConsentSource -Budget $budget -Context $ctx
}
