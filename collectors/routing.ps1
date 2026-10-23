# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'routing': IPv4/IPv6 route tables (active and persistent), IP
# interfaces with metrics and forwarding, IP addresses, global IP routing,
# MAC bridges and Internet Connection Sharing.
# Schema: docs/schema/routing.md. Read-only. Admin rights are needed only for
# the ICS connection list (HNetCfg returns nothing without them).

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

# Targets for route selection. Documentation prefixes (RFC 5737, RFC 3849)
# never appear in real route tables, so the lookup shows the path an
# arbitrary Internet address would take. Find-NetRoute is a local route table
# query: no packets are sent.
$ExternalTargets = @(
    @{ kind = 'externalIPv4'; target = '192.0.2.1' }
    @{ kind = 'externalIPv6'; target = '2001:db8::1' }
)

function Get-MetricKey {
    param($InterfaceIndex, $AddressFamily)
    '{0}|{1}' -f [int]$InterfaceIndex, [string]$AddressFamily
}

function Get-EffectiveMetric {
    # Windows picks the route with the lowest route metric + interface metric.
    # Returns @(interfaceMetric, effectiveMetric); unknown parts give null.
    param($RouteMetric, $InterfaceMetric)
    if ($null -eq $RouteMetric -or $null -eq $InterfaceMetric) { return @($InterfaceMetric, $null) }
    @($InterfaceMetric, ([int64]$RouteMetric + [int64]$InterfaceMetric))
}

function ConvertTo-RouteRecord {
    # $MetricMap: "ifIndex|family" -> interface metric, or $null if unknown.
    param($Route, [hashtable] $MetricMap)
    $ifMetric = $null
    if ($null -ne $MetricMap) { $ifMetric = $MetricMap[(Get-MetricKey $Route.InterfaceIndex $Route.AddressFamily)] }
    $metrics = Get-EffectiveMetric $Route.RouteMetric $ifMetric
    [ordered]@{
        addressFamily     = $Route.AddressFamily
        destinationPrefix = $Route.DestinationPrefix
        nextHop           = $Route.NextHop
        interfaceIndex    = [int]$Route.InterfaceIndex
        interfaceAlias    = $Route.InterfaceAlias
        routeMetric       = $Route.RouteMetric
        interfaceMetric   = $metrics[0]
        effectiveMetric   = $metrics[1]
        protocol          = $Route.Protocol
        publish           = $Route.Publish
    }
}

function Find-RouteSelection {
    # Returns the route Windows selects for $Target: source address, route
    # and effective metric. "Network unreachable" (Win32 1231) is a result
    # (reachable = false), not an error; other errors are thrown.
    param([string] $Kind, [string] $Target, [hashtable] $MetricMap)

    $record = [ordered]@{
        kind              = $Kind
        target            = $Target
        reachable         = $false
        sourceAddress     = $null
        interfaceIndex    = $null
        interfaceAlias    = $null
        destinationPrefix = $null
        nextHop           = $null
        routeMetric       = $null
        interfaceMetric   = $null
        effectiveMetric   = $null
    }
    try {
        $found = @(Find-NetRoute -RemoteIPAddress $Target -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'Windows System Error 1231,*') { return $record }
        throw
    }

    foreach ($item in $found) {
        switch ($item.CimClass.CimClassName) {
            'MSFT_NetIPAddress' { $record.sourceAddress = $item.IPAddress }
            'MSFT_NetRoute' {
                $route = ConvertTo-RouteRecord -Route $item -MetricMap $MetricMap
                $record.reachable = $true
                foreach ($key in 'interfaceIndex', 'interfaceAlias', 'destinationPrefix', 'nextHop', 'routeMetric', 'interfaceMetric', 'effectiveMetric') {
                    $record[$key] = $route[$key]
                }
            }
        }
    }
    $record
}

function Test-Enabled {
    # NetIPInterface flags are Enabled/Disabled enums; null stays null.
    param($Value)
    if ($null -eq $Value) { return $null }
    [string]$Value -eq 'Enabled'
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'routing' -Version '1.1.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)

    $interfaces = Invoke-Source -Context $ctx -Source 'Get-NetIPInterface' -AsList -ScriptBlock {
        Get-NetIPInterface -ErrorAction Stop | Sort-Object InterfaceIndex, AddressFamily | ForEach-Object {
            [ordered]@{
                interfaceIndex      = [int]$_.InterfaceIndex
                interfaceAlias      = $_.InterfaceAlias
                addressFamily       = $_.AddressFamily
                connectionState     = $_.ConnectionState
                interfaceMetric     = $_.InterfaceMetric
                automaticMetric     = Test-Enabled $_.AutomaticMetric
                forwarding          = Test-Enabled $_.Forwarding
                dhcp                = Test-Enabled $_.Dhcp
                ignoreDefaultRoutes = Test-Enabled $_.IgnoreDefaultRoutes
                weakHostSend        = Test-Enabled $_.WeakHostSend
                weakHostReceive     = Test-Enabled $_.WeakHostReceive
                nlMtu               = $_.NlMtu
            }
        }
    }

    # Interface metrics for effective route metrics; without interfaces they stay null.
    $metricMap = $null
    if ($null -ne $interfaces) {
        $metricMap = @{}
        foreach ($i in $interfaces) { $metricMap[(Get-MetricKey $i.interfaceIndex $i.addressFamily)] = $i.interfaceMetric }
    }

    $routes = Invoke-Source -Context $ctx -Source 'Get-NetRoute' -AsList -ScriptBlock {
        Get-NetRoute -ErrorAction Stop |
            Sort-Object AddressFamily, InterfaceIndex, DestinationPrefix, NextHop |
            ForEach-Object { ConvertTo-RouteRecord -Route $_ -MetricMap $metricMap }
    }

    $persistentRoutes = Invoke-Source -Context $ctx -Source 'Get-NetRoute -PolicyStore PersistentStore' -AsList -ScriptBlock {
        Invoke-AllowNotFound { Get-NetRoute -PolicyStore PersistentStore -ErrorAction Stop } |
            Sort-Object AddressFamily, InterfaceIndex, DestinationPrefix |
            ForEach-Object { ConvertTo-RouteRecord -Route $_ -MetricMap $metricMap }
    }

    # Route selection: external IPv4/IPv6 and every default gateway. Each
    # target is its own source so one failure does not hide the others.
    $targets = New-Object System.Collections.Generic.List[object]
    foreach ($t in $ExternalTargets) { $targets.Add($t) }
    if ($null -ne $routes) {
        $gateways = $routes |
            Where-Object { $_.destinationPrefix -in '0.0.0.0/0', '::/0' -and $_.nextHop -notin '0.0.0.0', '::' } |
            ForEach-Object { $_.nextHop } | Sort-Object -Unique
        foreach ($g in $gateways) { $targets.Add(@{ kind = 'gateway'; target = $g }) }
    }
    $routeSelection = @(foreach ($t in $targets) {
            $selected = Invoke-Source -Context $ctx -Source "Find-NetRoute $($t.target)" -ScriptBlock {
                Find-RouteSelection -Kind $t.kind -Target $t.target -MetricMap $metricMap
            }
            if ($null -eq $selected) {
                # Lookup failed (recorded in errors): keep the target with unknown result.
                $selected = [ordered]@{ kind = $t.kind; target = $t.target; reachable = $null }
            }
            $selected
        })

    $addresses = Invoke-Source -Context $ctx -Source 'Get-NetIPAddress' -AsList -ScriptBlock {
        Get-NetIPAddress -ErrorAction Stop | Sort-Object InterfaceIndex, AddressFamily, IPAddress | ForEach-Object {
            [ordered]@{
                interfaceIndex = [int]$_.InterfaceIndex
                interfaceAlias = $_.InterfaceAlias
                addressFamily  = $_.AddressFamily
                ipAddress      = $_.IPAddress
                prefixLength   = [int]$_.PrefixLength
                prefixOrigin   = $_.PrefixOrigin
                suffixOrigin   = $_.SuffixOrigin
                addressState   = $_.AddressState
                skipAsSource   = [bool]$_.SkipAsSource
            }
        }
    }

    $ipEnableRouter = Invoke-Source -Context $ctx -Source 'IPEnableRouter' -ScriptBlock {
        $value = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'IPEnableRouter'
        if ($null -eq $value) { return [ordered]@{ value = $null } }
        [ordered]@{ value = [int]$value -eq 1 }
    }

    $bridge = Invoke-Source -Context $ctx -Source 'bridge' -ScriptBlock {
        # The MAC Bridge miniport has component ID ms_bridgemp; member
        # adapters have the ms_bridge protocol bound and enabled.
        $miniports = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.ComponentID -eq 'ms_bridgemp' })
        $bindings = Invoke-AllowNotFound { Get-NetAdapterBinding -ComponentID ms_bridge -IncludeHidden -ErrorAction Stop }
        $members = @($bindings | Where-Object { $_.Enabled })
        $byName = @{}
        foreach ($a in (Get-NetAdapter -IncludeHidden -ErrorAction Stop)) { $byName[$a.Name] = $a }
        [ordered]@{
            adapters = @($miniports | ForEach-Object {
                    [ordered]@{ name = $_.Name; interfaceIndex = [int]$_.InterfaceIndex; status = $_.Status }
                })
            members  = @($members | ForEach-Object {
                    $idx = if ($byName.ContainsKey($_.Name)) { [int]$byName[$_.Name].InterfaceIndex } else { $null }
                    [ordered]@{ name = $_.Name; interfaceIndex = $idx }
                })
        }
    }

    $icsService = Invoke-Source -Context $ctx -Source 'SharedAccess' -ScriptBlock {
        $svc = Get-Service -Name SharedAccess -ErrorAction Stop
        [ordered]@{
            status       = $svc.Status
            startType    = $svc.StartType
            # The private (shared-to) side of ICS gets this address.
            scopeAddress = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters' 'ScopeAddress'
        }
    }

    $icsConnections = Invoke-Source -Context $ctx -Source 'HNetCfg.HNetShare' -AsList -RequiresAdmin -ScriptBlock {
        $share = New-Object -ComObject HNetCfg.HNetShare
        foreach ($c in $share.EnumEveryConnection) {
            $props = $share.NetConnectionProps($c)
            $cfg = $share.INetSharingConfigurationForINetConnection($c)
            [ordered]@{
                name           = $props.Name
                deviceName     = $props.DeviceName
                guid           = ([string]$props.Guid).ToLowerInvariant()
                sharingEnabled = [bool]$cfg.SharingEnabled
                # 0 = public (shared) side, 1 = private side.
                sharingType    = if (-not $cfg.SharingEnabled) { $null } elseif ($cfg.SharingConnectionType -eq 0) { 'Public' } else { 'Private' }
            }
        }
    }

    [ordered]@{
        routes           = $routes
        persistentRoutes = $persistentRoutes
        routeSelection   = $routeSelection
        interfaces       = $interfaces
        addresses        = $addresses
        ipEnableRouter   = if ($null -ne $ipEnableRouter) { $ipEnableRouter.value } else { $null }
        bridge           = $bridge
        ics              = [ordered]@{
            service     = $icsService
            connections = $icsConnections
        }
    }
}
