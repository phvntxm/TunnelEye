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

function ConvertTo-RouteRecord {
    param($Route)
    [ordered]@{
        addressFamily     = $Route.AddressFamily
        destinationPrefix = $Route.DestinationPrefix
        nextHop           = $Route.NextHop
        interfaceIndex    = [int]$Route.InterfaceIndex
        interfaceAlias    = $Route.InterfaceAlias
        routeMetric       = $Route.RouteMetric
        protocol          = $Route.Protocol
        publish           = $Route.Publish
    }
}

function Test-Enabled {
    # NetIPInterface flags are Enabled/Disabled enums; null stays null.
    param($Value)
    if ($null -eq $Value) { return $null }
    [string]$Value -eq 'Enabled'
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'routing' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)

    $routes = Invoke-Source -Context $ctx -Source 'Get-NetRoute' -AsList -ScriptBlock {
        Get-NetRoute -ErrorAction Stop |
            Sort-Object AddressFamily, InterfaceIndex, DestinationPrefix, NextHop |
            ForEach-Object { ConvertTo-RouteRecord $_ }
    }

    $persistentRoutes = Invoke-Source -Context $ctx -Source 'Get-NetRoute -PolicyStore PersistentStore' -AsList -ScriptBlock {
        Invoke-AllowNotFound { Get-NetRoute -PolicyStore PersistentStore -ErrorAction Stop } |
            Sort-Object AddressFamily, InterfaceIndex, DestinationPrefix | ForEach-Object { ConvertTo-RouteRecord $_ }
    }

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
