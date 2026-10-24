# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'connections': TCP listeners, UDP endpoints and TCP connections
# with their owning processes. Public remote addresses are never stored:
# such connections become counters (D-009).
# Schema: docs/schema/connections.md. Read-only; no admin rights required.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

function Split-TcpConnections {
    # Splits normalized connections (@{ state; localAddress; localPort;
    # remoteAddress; remotePort; processId; process }) into full entries
    # (non-public remote) and counters for public remotes keyed by process,
    # process id, local address and remote port (D-009). Public addresses
    # are only counted, never returned.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Connections)
    $entries = [System.Collections.Generic.List[object]]::new()
    $groups = [ordered]@{}
    foreach ($c in $Connections) {
        $class = Get-AddressClass $c['remoteAddress']
        if ($class -ne 'public') {
            $entries.Add([ordered]@{
                    state         = $c['state']
                    localAddress  = $c['localAddress']
                    localPort     = $c['localPort']
                    remoteAddress = $c['remoteAddress']
                    remotePort    = $c['remotePort']
                    remoteClass   = $class
                    processId     = $c['processId']
                    process       = $c['process']
                })
            continue
        }
        $key = '{0}|{1}|{2}|{3}' -f $c['process'], $c['processId'], $c['localAddress'], $c['remotePort']
        if (-not $groups.Contains($key)) {
            $groups[$key] = @{
                process      = $c['process']
                processId    = $c['processId']
                localAddress = $c['localAddress']
                remotePort   = $c['remotePort']
                count        = 0
                states       = [ordered]@{}
                remotes      = @{}
            }
        }
        $g = $groups[$key]
        $g.count++
        if (-not $g.states.Contains([string]$c['state'])) { $g.states[[string]$c['state']] = 0 }
        $g.states[[string]$c['state']]++
        $g.remotes[[string]$c['remoteAddress']] = $true
    }
    $public = @(foreach ($g in $groups.Values) {
            [ordered]@{
                process               = $g.process
                processId             = $g.processId
                localAddress          = $g.localAddress
                remotePort            = $g.remotePort
                connections           = $g.count
                uniqueRemoteAddresses = $g.remotes.Count
                byState               = @(foreach ($s in $g.states.Keys) { [ordered]@{ state = $s; count = $g.states[$s] } })
            }
        })
    [pscustomobject]@{ Entries = $entries.ToArray(); Public = $public }
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'connections' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)

    # Names only: paths and command lines may reveal the user and secrets.
    $processNames = @{}
    $processes = Invoke-Source -Context $ctx -Source 'Get-Process' -AsList -ScriptBlock {
        Get-Process -ErrorAction Stop | ForEach-Object { @{ id = [int]$_.Id; name = $_.ProcessName } }
    }
    foreach ($p in @($processes)) { if ($null -ne $p) { $processNames[$p.id] = $p.name } }
    $nameOf = { param($processId) if ($processNames.ContainsKey([int]$processId)) { $processNames[[int]$processId] } else { $null } }

    $tcp = Invoke-Source -Context $ctx -Source 'Get-NetTCPConnection' -AsList -ScriptBlock {
        Invoke-AllowNotFound { Get-NetTCPConnection -ErrorAction Stop } | ForEach-Object {
            @{
                state         = [string]$_.State
                localAddress  = $_.LocalAddress
                localPort     = [int]$_.LocalPort
                remoteAddress = $_.RemoteAddress
                remotePort    = [int]$_.RemotePort
                processId     = [int]$_.OwningProcess
                process       = & $nameOf $_.OwningProcess
            }
        }
    }
    $udp = Invoke-Source -Context $ctx -Source 'Get-NetUDPEndpoint' -AsList -ScriptBlock {
        Invoke-AllowNotFound { Get-NetUDPEndpoint -ErrorAction Stop } | Sort-Object LocalAddress, LocalPort | ForEach-Object {
            [ordered]@{
                localAddress = $_.LocalAddress
                localPort    = [int]$_.LocalPort
                localClass   = Get-AddressClass $_.LocalAddress
                processId    = [int]$_.OwningProcess
                process      = & $nameOf $_.OwningProcess
            }
        }
    }

    $listeners = $null
    $connections = $null
    $publicConnections = $null
    if ($null -ne $tcp) {
        $listeners = @($tcp | Where-Object { $_['state'] -eq 'Listen' } | Sort-Object { $_['localAddress'] }, { $_['localPort'] } | ForEach-Object {
                [ordered]@{
                    localAddress = $_['localAddress']
                    localPort    = $_['localPort']
                    localClass   = Get-AddressClass $_['localAddress']
                    processId    = $_['processId']
                    process      = $_['process']
                }
            })
        $others = @($tcp | Where-Object { $_['state'] -ne 'Listen' } | Sort-Object { $_['localAddress'] }, { $_['localPort'] }, { $_['remotePort'] })
        $split = Split-TcpConnections -Connections $others
        $connections = $split.Entries
        $publicConnections = @($split.Public | Sort-Object { $_['process'] }, { $_['localAddress'] }, { $_['remotePort'] })
    }

    [ordered]@{
        tcpListeners      = $listeners
        udpEndpoints      = $udp
        tcpConnections    = $connections
        publicConnections = $publicConnections
    }
}
