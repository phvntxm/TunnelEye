# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'tcp-stack': TCP setting templates (auto-tuning, congestion
# provider, ECN, ...), transport filters, global offloads (RSS, RSC,
# chimney), 'netsh int tcp show global' and registry tweaks of the TCP/IP
# stack that tuning tools leave behind (global and per interface).
# Schema: docs/schema/tcp-stack.md. Read-only.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

$TcpipKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
# Allow-list: the same key also holds the host name, domain and DNS servers,
# which are not collected here.
$TweakKeys = @(
    @{ scope = 'tcpip'; path = $TcpipKey; names = @(
            'Tcp1323Opts', 'TcpWindowSize', 'GlobalMaxTcpWindowSize', 'DefaultTTL', 'MaxUserPort', 'TcpTimedWaitDelay',
            'TcpMaxDataRetransmissions', 'TcpMaxConnectRetransmissions', 'EnablePMTUDiscovery', 'EnablePMTUBHDetect',
            'SackOpts', 'TcpNumConnections', 'DisableTaskOffload', 'EnableTCPChimney', 'EnableRSS', 'EnableTCPA',
            'TcpAckFrequency', 'TCPNoDelay', 'TcpDelAckTicks', 'DeadGWDetectDefault', 'EnableDca', 'KeepAliveTime', 'KeepAliveInterval') }
    @{ scope = 'tcpip6'; path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; names = @('DisabledComponents') }
    @{ scope = 'afd'; path = 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters'; names = @(
            'DefaultReceiveWindow', 'DefaultSendWindow', 'FastSendDatagramThreshold', 'FastCopyReceiveThreshold', 'IgnorePushBitOnReceives', 'NonBlockingSendSpecialBuffering') }
    @{ scope = 'multimedia'; path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'; names = @('NetworkThrottlingIndex', 'SystemResponsiveness') }
    @{ scope = 'qosPolicy'; path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched'; names = @('NonBestEffortLimit', 'TimerResolution') }
)
$InterfaceTweakNames = 'TcpAckFrequency', 'TCPNoDelay', 'TcpDelAckTicks', 'MTU', 'TcpWindowSize'

function ConvertTo-TweakValue {
    # Registry DWORD/QWORD as a number, strings as strings, binary as hex.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [int] -or $Value -is [long]) { return $Value }
    if ($Value -is [byte[]]) { return ([BitConverter]::ToString($Value) -replace '-', '').ToLowerInvariant() }
    if ($Value -is [string[]]) { return , @($Value) }
    [string]$Value
}

function Get-RegistryTweaks {
    # Values from an allow-list that are present in a key: [{ name, value }].
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string[]] $Names)
    if (-not (Test-Path -LiteralPath $Path)) { return , @() }
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    $present = @($key.GetValueNames())
    , @(foreach ($n in $Names) {
            $match = @($present | Where-Object { $_ -eq $n })
            if ($match.Count) { [ordered]@{ name = $match[0]; value = ConvertTo-TweakValue $key.GetValue($match[0], $null, 'DoNotExpandEnvironmentNames') } }
        })
}

function ConvertFrom-NetshTcpGlobal {
    # 'netsh int tcp show global' prints "Label : value" lines; labels and
    # values are localized and the set of lines differs between Windows
    # versions, so lines are kept as pairs in order, not mapped to fields.
    param([AllowEmptyString()][string] $Text)
    , @(foreach ($line in ($Text -split '\r?\n')) {
            if ($line -match '^\s*(.+?)\s+:\s*(.*?)\s*$') { [ordered]@{ label = $Matches[1]; value = $Matches[2] } }
        })
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'tcp-stack' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)

    $settings = Invoke-Source -Context $ctx -Source 'Get-NetTCPSetting' -AsList -ScriptBlock {
        Get-NetTCPSetting -ErrorAction Stop | Sort-Object SettingName | ForEach-Object {
            [ordered]@{
                settingName                   = [string]$_.SettingName
                autoTuningLevelLocal          = if ($null -ne $_.AutoTuningLevelLocal) { [string]$_.AutoTuningLevelLocal } else { $null }
                autoTuningLevelEffective      = if ($null -ne $_.AutoTuningLevelEffective) { [string]$_.AutoTuningLevelEffective } else { $null }
                autoTuningLevelGroupPolicy    = if ($null -ne $_.AutoTuningLevelGroupPolicy) { [string]$_.AutoTuningLevelGroupPolicy } else { $null }
                scalingHeuristics             = if ($null -ne $_.ScalingHeuristics) { [string]$_.ScalingHeuristics } else { $null }
                congestionProvider            = if ($null -ne $_.CongestionProvider) { [string]$_.CongestionProvider } else { $null }
                ecnCapability                 = if ($null -ne $_.EcnCapability) { [string]$_.EcnCapability } else { $null }
                timestamps                    = if ($null -ne $_.Timestamps) { [string]$_.Timestamps } else { $null }
                initialRtoMs                  = $_.InitialRtoMs
                minRtoMs                      = $_.MinRtoMs
                delayedAckTimeoutMs           = $_.DelayedAckTimeoutMs
                delayedAckFrequency           = $_.DelayedAckFrequency
                maxSynRetransmissions         = $_.MaxSynRetransmissions
                initialCongestionWindowMss    = $_.InitialCongestionWindowMss
                cwndRestart                   = if ($null -ne $_.CwndRestart) { [string]$_.CwndRestart } else { $null }
                nonSackRttResiliency          = if ($null -ne $_.NonSackRttResiliency) { [string]$_.NonSackRttResiliency } else { $null }
                memoryPressureProtection      = if ($null -ne $_.MemoryPressureProtection) { [string]$_.MemoryPressureProtection } else { $null }
                automaticUseCustom            = if ($null -ne $_.AutomaticUseCustom) { [string]$_.AutomaticUseCustom } else { $null }
                dynamicPortRangeStartPort     = $_.DynamicPortRangeStartPort
                dynamicPortRangeNumberOfPorts = $_.DynamicPortRangeNumberOfPorts
            }
        }
    }

    # Which template applies to which ports/prefixes; admin only.
    $transportFilters = Invoke-Source -Context $ctx -Source 'Get-NetTransportFilter' -AsList -RequiresAdmin -ScriptBlock {
        Invoke-AllowNotFound { Get-NetTransportFilter -ErrorAction Stop } | ForEach-Object {
            [ordered]@{
                settingName           = [string]$_.SettingName
                protocol              = [string]$_.Protocol
                localPortStart        = $_.LocalPortStart
                localPortEnd          = $_.LocalPortEnd
                remotePortStart       = $_.RemotePortStart
                remotePortEnd         = $_.RemotePortEnd
                destinationPrefix     = $_.DestinationPrefix
            }
        }
    }

    $offload = Invoke-Source -Context $ctx -Source 'Get-NetOffloadGlobalSetting' -ScriptBlock {
        $o = Get-NetOffloadGlobalSetting -ErrorAction Stop
        [ordered]@{
            receiveSideScaling           = [string]$o.ReceiveSideScaling
            receiveSegmentCoalescing     = [string]$o.ReceiveSegmentCoalescing
            chimney                      = [string]$o.Chimney
            taskOffload                  = [string]$o.TaskOffload
            networkDirect                = [string]$o.NetworkDirect
            networkDirectAcrossIPSubnets = [string]$o.NetworkDirectAcrossIPSubnets
            packetCoalescingFilter       = [string]$o.PacketCoalescingFilter
        }
    }

    $netshGlobal = $null
    $netsh = Invoke-NativeCommand -Context $ctx -Source 'netsh int tcp show global' `
        -FilePath (Join-Path $env:SystemRoot 'System32\netsh.exe') -ArgumentList 'int', 'tcp', 'show', 'global'
    if ($null -ne $netsh -and $netsh.exitCode -eq 0) {
        $netshGlobal = [ordered]@{
            values = ConvertFrom-NetshTcpGlobal $netsh.stdout
            raw    = $netsh.stdout.Trim()
        }
    }

    $tweaks = Invoke-Source -Context $ctx -Source 'registry tweaks' -AsList -ScriptBlock {
        foreach ($k in $TweakKeys) {
            [ordered]@{ scope = $k.scope; values = Get-RegistryTweaks -Path $k.path -Names $k.names }
        }
    }
    $interfaceTweaks = Invoke-Source -Context $ctx -Source 'registry interface tweaks' -AsList -ScriptBlock {
        foreach ($family in @(@{ name = 'IPv4'; path = "$TcpipKey\Interfaces" }, @{ name = 'IPv6'; path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces' })) {
            if (-not (Test-Path -LiteralPath $family.path)) { continue }
            foreach ($item in (Get-ChildItem -LiteralPath $family.path -ErrorAction Stop | Sort-Object PSChildName)) {
                $values = Get-RegistryTweaks -Path $item.PSPath -Names $InterfaceTweakNames
                if ($values.Count) {
                    [ordered]@{ interfaceGuid = $item.PSChildName.ToLowerInvariant(); addressFamily = $family.name; values = $values }
                }
            }
        }
    }

    [ordered]@{
        settings         = $settings
        transportFilters = $transportFilters
        offload          = $offload
        netshGlobal      = $netshGlobal
        registry         = [ordered]@{
            global     = $tweaks
            interfaces = $interfaceTweaks
        }
    }
}
