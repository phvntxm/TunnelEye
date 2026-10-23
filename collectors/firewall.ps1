# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'firewall': Windows Firewall profiles and rules (effective policy,
# ActiveStore) with their application, port and address filters, third-party
# firewall products registered in Security Center, and the firewall services.
# WFP providers, sublayers, callouts and filters: admin only (netsh wfp).
# Schema: docs/schema/firewall.md. Read-only.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

$FirewallServiceNames = 'mpssvc', 'BFE'

function ConvertTo-FlagList {
    # Flag enums print as "Domain, Private"; returns @('Domain', 'Private').
    param($Value)
    if ($null -eq $Value) { return , @() }
    , @(([string]$Value) -split ',\s*' | Where-Object { $_ -ne '' })
}

function ConvertTo-StringList {
    # Filter values come as a string or string[]; always returns an array.
    param($Value)
    if ($null -eq $Value) { return , @() }
    , @(@($Value) | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
}

function ConvertFrom-SecurityCenterState {
    # productState of Security Center products: byte 2 = 0x10 enabled
    # (0x00/0x01 off/snoozed); byte 3 = 0x00 up to date, 0x10 out of date.
    param($ProductState)
    if ($null -eq $ProductState) { return @{ enabled = $null; upToDate = $null } }
    $state = [int64]$ProductState
    @{
        enabled  = (($state -shr 8) -band 0xF0) -eq 0x10
        upToDate = ($state -band 0xF0) -eq 0x00
    }
}

function Get-XmlText {
    # Text of the first node matching an XPath, or $null if absent or empty.
    param($Node, [string] $XPath)
    $n = $Node.SelectSingleNode($XPath)
    if ($null -eq $n -or $n.InnerText -eq '') { return $null }
    $n.InnerText
}

function Get-XmlTextList {
    param($Node, [string] $XPath)
    , @(foreach ($n in $Node.SelectNodes($XPath)) { if ($n.InnerText -ne '') { $n.InnerText } })
}

function Read-WfpStateXml {
    # 'netsh wfp show state' writes several root elements in one file
    # (<wfpstate>, then <firewallState>, ...); returns the <wfpstate> element
    # as an XmlDocument, or $null if it is not there.
    param([Parameter(Mandatory)][string] $Path)
    $settings = New-Object Xml.XmlReaderSettings
    $settings.ConformanceLevel = [Xml.ConformanceLevel]::Fragment
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create($Path, $settings)
    try {
        [void]$reader.Read()
        while (-not $reader.EOF) {
            if ($reader.NodeType -eq [Xml.XmlNodeType]::Element -and $reader.Depth -eq 0) {
                if ($reader.Name -eq 'wfpstate') {
                    $doc = New-Object Xml.XmlDocument
                    $doc.XmlResolver = $null
                    $doc.Load($reader.ReadSubtree())
                    return $doc
                }
                # Skip() moves to the next sibling, so no Read() after it.
                $reader.Skip()
                continue
            }
            [void]$reader.Read()
        }
    }
    finally { $reader.Close() }
    $null
}

function ConvertFrom-WfpState {
    # Providers, sublayers, callouts and filters from the <wfpstate> document.
    # Not collected: sessions (user names), connected endpoints, IPsec SAs and
    # statistics, provider data and filter condition values (addresses, app
    # paths); conditions are kept as field + match type only.
    param([Parameter(Mandatory)][Xml.XmlDocument] $Document)
    $root = $Document.DocumentElement

    $providers = @(foreach ($p in $root.SelectNodes('providers/item')) {
            [ordered]@{
                providerKey = Get-XmlText $p 'providerKey'
                name        = Hide-UserProfilePath (Get-XmlText $p 'displayData/name')
                serviceName = Get-XmlText $p 'serviceName'
                flags       = Get-XmlTextList $p 'flags/item'
            }
        })
    $subLayers = @(foreach ($s in $root.SelectNodes('subLayers/item')) {
            $weight = Get-XmlText $s 'weight'
            [ordered]@{
                subLayerKey = Get-XmlText $s 'subLayerKey'
                name        = Hide-UserProfilePath (Get-XmlText $s 'displayData/name')
                providerKey = Get-XmlText $s 'providerKey'
                weight      = if ($null -ne $weight) { [int]$weight } else { $null }
                flags       = Get-XmlTextList $s 'flags/item'
            }
        })

    $callouts = [System.Collections.Generic.List[object]]::new()
    $filters = [System.Collections.Generic.List[object]]::new()
    foreach ($layer in $root.SelectNodes('layers/item')) {
        foreach ($c in $layer.SelectNodes('callouts/item')) {
            $id = Get-XmlText $c 'calloutId'
            $callouts.Add([ordered]@{
                    calloutKey      = Get-XmlText $c 'calloutKey'
                    calloutId       = if ($null -ne $id) { [int64]$id } else { $null }
                    name            = Hide-UserProfilePath (Get-XmlText $c 'displayData/name')
                    providerKey     = Get-XmlText $c 'providerKey'
                    applicableLayer = Get-XmlText $c 'applicableLayer'
                    flags           = Get-XmlTextList $c 'flags/item'
                })
        }
        foreach ($f in $layer.SelectNodes('filters/item')) {
            $id = Get-XmlText $f 'filterId'
            $actionType = Get-XmlText $f 'action/type'
            $weightType = Get-XmlText $f 'weight/type'
            $conditions = @(foreach ($cond in $f.SelectNodes('filterCondition/item')) {
                    [ordered]@{ fieldKey = Get-XmlText $cond 'fieldKey'; matchType = Get-XmlText $cond 'matchType' }
                })
            # 64-bit weights exceed the exact integer range of JSON numbers in
            # most readers, so weights are kept as decimal strings.
            $filters.Add([ordered]@{
                    filterId        = if ($null -ne $id) { [int64]$id } else { $null }
                    filterKey       = Get-XmlText $f 'filterKey'
                    name            = Hide-UserProfilePath (Get-XmlText $f 'displayData/name')
                    providerKey     = Get-XmlText $f 'providerKey'
                    layerKey        = Get-XmlText $f 'layerKey'
                    subLayerKey     = Get-XmlText $f 'subLayerKey'
                    action          = $actionType
                    calloutKey      = if ($actionType -like 'FWP_ACTION_CALLOUT*') { Get-XmlText $f 'action/filterType' } else { $null }
                    weight          = if ($weightType -and $weightType -ne 'FWP_EMPTY') { Get-XmlText $f ('weight/' + $weightType.Substring(4).ToLowerInvariant()) } else { $null }
                    effectiveWeight = Get-XmlText $f 'effectiveWeight/uint64'
                    flags           = Get-XmlTextList $f 'flags/item'
                    conditions      = $conditions
                })
        }
    }

    [ordered]@{
        providers            = $providers
        subLayers            = $subLayers
        callouts             = $callouts.ToArray()
        filters              = @($filters | Sort-Object { $_['filterId'] })
        providerContextCount = $root.SelectNodes('providerContexts/item').Count
    }
}

function Group-ByInstanceId {
    param([object[]] $Items)
    $map = @{}
    foreach ($item in $Items) { if ($null -ne $item -and $item.InstanceID) { $map[$item.InstanceID] = $item } }
    $map
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'firewall' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)

    $profiles = Invoke-Source -Context $ctx -Source 'Get-NetFirewallProfile' -AsList -ScriptBlock {
        Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Sort-Object Name | ForEach-Object {
            [ordered]@{
                name                     = $_.Name
                enabled                  = [string]$_.Enabled -eq 'True'
                defaultInboundAction     = $_.DefaultInboundAction
                defaultOutboundAction    = $_.DefaultOutboundAction
                allowInboundRules        = $_.AllowInboundRules
                allowLocalFirewallRules  = $_.AllowLocalFirewallRules
                notifyOnListen           = $_.NotifyOnListen
                disabledInterfaceAliases = ConvertTo-StringList $_.DisabledInterfaceAliases
                logAllowed               = $_.LogAllowed
                logBlocked               = $_.LogBlocked
                logFileName              = Hide-UserProfilePath $_.LogFileName
            }
        }
    }

    $rawRules = Invoke-Source -Context $ctx -Source 'Get-NetFirewallRule' -AsList -ScriptBlock {
        Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop
    }
    # Filters are read in bulk and joined by InstanceID: per-rule calls take
    # minutes. Without admin rights port filters come back partially and
    # address filters not at all; the error is recorded, rules stay.
    $appFilters = Invoke-Source -Context $ctx -Source 'Get-NetFirewallApplicationFilter' -AsList -ScriptBlock {
        Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore
    }
    $portFilters = Invoke-Source -Context $ctx -Source 'Get-NetFirewallPortFilter' -AsList -ScriptBlock {
        Get-NetFirewallPortFilter -All -PolicyStore ActiveStore
    }
    $addressFilters = Invoke-Source -Context $ctx -Source 'Get-NetFirewallAddressFilter' -AsList -ScriptBlock {
        Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore
    }

    $rules = $null
    if ($null -ne $rawRules) {
        $appById = Group-ByInstanceId $appFilters
        $portById = Group-ByInstanceId $portFilters
        $addressById = Group-ByInstanceId $addressFilters
        $rules = @($rawRules | Sort-Object Name | ForEach-Object {
                $r = $_
                $app = $appById[$r.InstanceID]
                $port = $portById[$r.InstanceID]
                $address = $addressById[$r.InstanceID]
                [ordered]@{
                    name                  = Hide-UserProfilePath $r.Name
                    displayName           = Hide-UserProfilePath $r.DisplayName
                    displayGroup          = if ($r.DisplayGroup) { $r.DisplayGroup } else { $null }
                    enabled               = [string]$r.Enabled -eq 'True'
                    direction             = $r.Direction
                    action                = $r.Action
                    profiles              = ConvertTo-FlagList $r.Profile
                    edgeTraversalPolicy   = $r.EdgeTraversalPolicy
                    policyStoreSourceType = $r.PolicyStoreSourceType
                    primaryStatus         = $r.PrimaryStatus
                    # Filters missing from a partial read are null, not "any".
                    program               = if ($null -ne $app) { Hide-UserProfilePath $app.Program } else { $null }
                    service               = if ($null -ne $app -and $app.Service -and $app.Service -ne 'Any') { $app.Service } else { $null }
                    package               = if ($null -ne $app -and $app.Package) { $app.Package } else { $null }
                    protocol              = if ($null -ne $port) { [string]$port.Protocol } else { $null }
                    localPorts            = if ($null -ne $port) { ConvertTo-StringList $port.LocalPort } else { $null }
                    remotePorts           = if ($null -ne $port) { ConvertTo-StringList $port.RemotePort } else { $null }
                    localAddresses        = if ($null -ne $address) { ConvertTo-StringList $address.LocalAddress } else { $null }
                    remoteAddresses       = if ($null -ne $address) { ConvertTo-StringList $address.RemoteAddress } else { $null }
                }
            })
    }

    # Security Center exists on client Windows only; on Server the namespace
    # is missing and the field is null with a NotSupported error.
    $products = Invoke-Source -Context $ctx -Source 'SecurityCenter2 FirewallProduct' -AsList -ScriptBlock {
        Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct -ErrorAction Stop | Sort-Object displayName | ForEach-Object {
            $state = ConvertFrom-SecurityCenterState $_.productState
            [ordered]@{
                displayName  = $_.displayName
                productState = $_.productState
                enabled      = $state.enabled
                upToDate     = $state.upToDate
            }
        }
    }

    $services = Invoke-Source -Context $ctx -Source 'Win32_Service' -AsList -ScriptBlock {
        $filter = ($FirewallServiceNames | ForEach-Object { "Name='$_'" }) -join ' OR '
        Get-CimInstance -ClassName Win32_Service -Filter $filter -ErrorAction Stop | Sort-Object Name | ForEach-Object {
            [ordered]@{ name = $_.Name; state = $_.State; startMode = $_.StartMode }
        }
    }

    # WFP: netsh can only write the state to a file. It goes to a unique temp
    # file that is deleted right after parsing; nothing else is written.
    $wfp = $null
    if (-not $ctx.Elevated) {
        Add-CollectorError -Context $ctx -Source 'netsh wfp show state' -Kind AccessDenied -Message 'Requires administrator rights; source skipped.'
    }
    else {
        $stateFile = Join-Path ([IO.Path]::GetTempPath()) ('tunneleye-wfp-{0}.xml' -f [guid]::NewGuid().ToString('N'))
        try {
            $netsh = Invoke-NativeCommand -Context $ctx -Source 'netsh wfp show state' `
                -FilePath (Join-Path $env:SystemRoot 'System32\netsh.exe') -ArgumentList 'wfp', 'show', 'state', "file=$stateFile"
            if ($null -ne $netsh -and $netsh.exitCode -eq 0) {
                $wfp = Invoke-Source -Context $ctx -Source 'wfpstate.xml' -ScriptBlock {
                    if (-not (Test-Path -LiteralPath $stateFile)) { throw (New-Object IO.FileNotFoundException('netsh did not write the WFP state file.')) }
                    $doc = Read-WfpStateXml -Path $stateFile
                    if ($null -eq $doc) { throw 'No <wfpstate> element in the netsh output.' }
                    ConvertFrom-WfpState -Document $doc
                }
            }
        }
        finally {
            Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
        }
    }

    [ordered]@{
        profiles = $profiles
        rules    = $rules
        products = $products
        services = $services
        wfp      = $wfp
    }
}
