# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'events': network-related events of the last 7 days - network
# adapter drivers, TCP/IP, NDIS, DHCP, DNS client, WLAN, network profile
# connects/disconnects, NCSI - as counters with timestamps. Messages and event
# data are not collected: they carry host names, addresses and SSIDs.
# Schema: docs/schema/events.md. Read-only; no admin rights required.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

$PeriodDays = 7
$MaxTimesPerGroup = 200
# Network components of Windows that log to System. Adapter drivers are added
# at run time (see Get-DriverProviderNames).
$SystemProviders = @(
    'Tcpip', 'Tcpip6', 'NDIS', 'Microsoft-Windows-NDIS', 'NetBT',
    'Microsoft-Windows-Dhcp-Client', 'Microsoft-Windows-DHCPv6-Client', 'Microsoft-Windows-DNS-Client',
    'Microsoft-Windows-WLAN-AutoConfig', 'Microsoft-Windows-Iphlpsvc', 'Microsoft-Windows-NlaSvc',
    'Microsoft-Windows-WWAN-SVC-EVENTS', 'RasSstp', 'Rasman', 'RemoteAccess', 'WinDivert'
)
# Operational logs: all events, or only the listed IDs (NetworkProfile logs
# many state events; only connect 10000 and disconnect 10001 matter here).
$OperationalLogs = @(
    @{ log = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; ids = $null }
    @{ log = 'Microsoft-Windows-NetworkProfile/Operational'; ids = @(10000, 10001) }
    @{ log = 'Microsoft-Windows-NCSI/Operational'; ids = $null }
    @{ log = 'Microsoft-Windows-Dhcp-Client/Admin'; ids = $null }
    @{ log = 'Microsoft-Windows-Dhcpv6-Client/Admin'; ids = $null }
)
$LevelNames = @{ 0 = 'Information'; 1 = 'Critical'; 2 = 'Error'; 3 = 'Warning'; 4 = 'Information'; 5 = 'Verbose' }

# Built-in VPN (SSTP, L2TP, IKEv2) logs connection errors to Application as
# RasClient, not to System.
$ApplicationProviders = @('RasClient')

function Get-DriverProviderNames {
    # A driver logs under the name of its service. For many drivers it equals
    # the driver file name (Netwtw14.sys / Netwtw14), for others it does not
    # (rt68cx21x64.sys / rt68cx21), so both are taken: an extra name in the
    # XPath costs nothing. Adapters: @{ driverFileName; serviceName }.
    param([AllowEmptyCollection()][object[]] $Adapters)
    $names = @(foreach ($a in $Adapters) {
            if ($null -eq $a) { continue }
            if ($a['driverFileName']) { [IO.Path]::GetFileNameWithoutExtension([string]$a['driverFileName']) }
            if ($a['serviceName']) { [string]$a['serviceName'] }
        })
    , @($names | Where-Object { $_ } | Sort-Object -Unique)
}

# The event log rejects an XPath with more than about 21 provider conditions
# ("The specified query is invalid"); providers are queried in chunks.
$ProvidersPerQuery = 15

function Split-IntoChunks {
    # Returns an array of arrays of at most $Size items.
    param([AllowEmptyCollection()][object[]] $Items, [int] $Size)
    $chunks = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $Items.Count; $i += $Size) {
        $chunks.Add(@($Items[$i..([Math]::Min($i + $Size, $Items.Count) - 1)]))
    }
    , $chunks.ToArray()
}

function New-EventXPath {
    # XPath for Get-WinEvent -FilterXPath: events of the last N days,
    # optionally of the given providers and IDs. Unlike -FilterHashtable, an
    # unknown provider name in XPath does not fail the query.
    param([int] $Days, [string[]] $Providers = @(), [int[]] $Ids = @())
    $parts = [System.Collections.Generic.List[string]]::new()
    $usable = @($Providers | Where-Object { $_ -match '^[\w.\-]+$' } | Select-Object -Unique)
    if ($usable.Count) { $parts.Add('Provider[' + (($usable | ForEach-Object { "@Name='$_'" }) -join ' or ') + ']') }
    if ($Ids.Count) { $parts.Add('(' + (($Ids | ForEach-Object { "EventID=$_" }) -join ' or ') + ')') }
    $parts.Add('TimeCreated[timediff(@SystemTime) <= ' + ([int64]$Days * 86400000) + ']')
    '*[System[' + ($parts -join ' and ') + ']]'
}

function Group-Events {
    # Counters per log, provider, event ID and level, with the newest
    # timestamps (up to $MaxTimes, newest first). Events: objects with
    # LogName, ProviderName, Id, Level, TimeCreated.
    param([AllowEmptyCollection()][object[]] $Events, [int] $MaxTimes = 200)
    $groups = [ordered]@{}
    foreach ($e in $Events) {
        if ($null -eq $e) { continue }
        $level = if ($null -ne $e.Level -and $LevelNames.ContainsKey([int]$e.Level)) { $LevelNames[[int]$e.Level] } else { [string]$e.Level }
        $key = '{0}|{1}|{2}|{3}' -f $e.LogName, $e.ProviderName, $e.Id, $level
        if (-not $groups.Contains($key)) {
            $groups[$key] = @{ logName = $e.LogName; provider = $e.ProviderName; eventId = [int]$e.Id; level = $level; times = [System.Collections.Generic.List[datetime]]::new() }
        }
        if ($null -ne $e.TimeCreated) { $groups[$key].times.Add(([datetime]$e.TimeCreated).ToUniversalTime()) }
    }
    $items = @(foreach ($g in $groups.Values) {
            $sorted = @($g.times | Sort-Object -Descending)
            [ordered]@{
                logName        = $g.logName
                provider       = $g.provider
                eventId        = $g.eventId
                level          = $g.level
                count          = $g.times.Count
                firstTime      = if ($sorted.Count) { Format-Timestamp $sorted[-1] } else { $null }
                lastTime       = if ($sorted.Count) { Format-Timestamp $sorted[0] } else { $null }
                times          = @($sorted | Select-Object -First $MaxTimes | ForEach-Object { Format-Timestamp $_ })
                timesTruncated = ($sorted.Count -gt $MaxTimes)
            }
        })
    , @($items | Sort-Object { $_['logName'] }, { $_['provider'] }, { $_['eventId'] })
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'events' -Version '1.1.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)
    $since = [datetime]::UtcNow.AddDays(-$PeriodDays)

    # Drivers of physical adapters (including VPN miniports, which Windows
    # counts as physical); virtual ones (Hyper-V switch, Wi-Fi Direct) are
    # left out: the Hyper-V switch alone logs thousands of events a week.
    $fromNetAdapter = Invoke-Source -Context $ctx -Source 'Get-NetAdapter' -AsList -ScriptBlock {
        Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object { @{ driverFileName = $_.DriverFileName; serviceName = $null } }
    }
    $fromCim = Invoke-Source -Context $ctx -Source 'Win32_NetworkAdapter' -AsList -ScriptBlock {
        Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'PhysicalAdapter = TRUE' -ErrorAction Stop |
            ForEach-Object { @{ driverFileName = $null; serviceName = $_.ServiceName } }
    }
    $driverProviders = Get-DriverProviderNames -Adapters @(@($fromNetAdapter) + @($fromCim))
    $providers = @(@($SystemProviders) + @($driverProviders))

    $all = [System.Collections.Generic.List[object]]::new()
    $queried = [System.Collections.Generic.List[object]]::new()
    $system = Invoke-Source -Context $ctx -Source 'System' -AsList -ScriptBlock {
        foreach ($chunk in (Split-IntoChunks -Items @($providers | Sort-Object -Unique) -Size $ProvidersPerQuery)) {
            Invoke-AllowNotFound { Get-WinEvent -LogName 'System' -FilterXPath (New-EventXPath -Days $PeriodDays -Providers $chunk) -ErrorAction Stop }
        }
    }
    $queried.Add(@{ logName = 'System'; ok = ($null -ne $system) })
    foreach ($e in @($system)) { if ($null -ne $e) { $all.Add($e) } }

    $application = Invoke-Source -Context $ctx -Source 'Application' -AsList -ScriptBlock {
        Invoke-AllowNotFound { Get-WinEvent -LogName 'Application' -FilterXPath (New-EventXPath -Days $PeriodDays -Providers $ApplicationProviders) -ErrorAction Stop }
    }
    $queried.Add(@{ logName = 'Application'; ok = ($null -ne $application) })
    foreach ($e in @($application)) { if ($null -ne $e) { $all.Add($e) } }

    foreach ($o in $OperationalLogs) {
        $ids = @()
        if ($null -ne $o.ids) { $ids = @($o.ids) }
        $events = Invoke-Source -Context $ctx -Source $o.log -AsList -ScriptBlock {
            # A missing or disabled log is not an error: it is reported in logs[].
            Invoke-AllowNotFound { Get-WinEvent -LogName $o.log -FilterXPath (New-EventXPath -Days $PeriodDays -Ids $ids) -ErrorAction Stop }
        }
        $queried.Add(@{ logName = $o.log; ok = ($null -ne $events) })
        foreach ($e in @($events)) { if ($null -ne $e) { $all.Add($e) } }
    }

    $logs = Invoke-Source -Context $ctx -Source 'Get-WinEvent -ListLog' -AsList -ScriptBlock {
        foreach ($q in $queried) {
            $info = $null
            try { $info = Get-WinEvent -ListLog $q.logName -ErrorAction Stop } catch { }
            [ordered]@{
                logName  = $q.logName
                exists   = ($null -ne $info)
                enabled  = if ($null -ne $info) { [bool]$info.IsEnabled } else { $null }
                readOk   = $q.ok
            }
        }
    }

    [ordered]@{
        periodDays = $PeriodDays
        since      = Format-Timestamp $since
        providers  = @($providers | Sort-Object -Unique)
        applicationProviders = $ApplicationProviders
        logs       = $logs
        groups     = Group-Events -Events $all.ToArray() -MaxTimes $MaxTimesPerGroup
    }
}
