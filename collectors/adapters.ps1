# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'adapters': all network adapters including hidden and virtual ones
# (TAP/TUN, Wintun, Hyper-V, WSL, VirtualBox, VMware), driver version, date and
# signature, protocol bindings, advanced properties, Net-class PnP devices
# (including non-present leftovers) and Net-class driver packages in the store.
# Schema: docs/schema/adapters.md. Read-only; no admin rights required.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

$NetClassGuid = '{4d36e972-e325-11ce-bfc1-08002be10318}'

function ConvertFrom-PnputilDrivers {
    # Parses 'pnputil /enum-drivers' output. Labels are localized, so fields
    # are taken by position and the block is accepted only if the positional
    # values have the expected shape. Returns Net-class packages, the raw text
    # of Net-class blocks and the number of Net-class blocks that did not parse.
    param([AllowEmptyString()][string] $Text)

    $packages = New-Object System.Collections.Generic.List[object]
    $rawBlocks = New-Object System.Collections.Generic.List[string]
    $unparsed = 0
    $inv = [Globalization.CultureInfo]::InvariantCulture

    foreach ($block in ($Text -split '\r?\n\s*\r?\n')) {
        $values = @($block -split '\r?\n' | Where-Object { $_ -match ':' } | ForEach-Object {
                $_.Substring($_.IndexOf(':') + 1).Trim()
            })
        if ($values.Count -lt 7) { continue }
        $isNet = $block -match [regex]::Escape($NetClassGuid)
        if (-not $isNet) { continue }
        $rawBlocks.Add($block.Trim())

        if ($values[0] -notmatch '^oem\d+\.inf$' -or $values[4] -notmatch '^\{[0-9a-fA-F-]{36}\}$') {
            $unparsed++
            continue
        }
        # "Driver Version" is "<date> <version>". The date is MM/dd/yyyy in
        # English output; other UI languages are not verified, so an
        # unrecognized date becomes null instead of a guess.
        $driverDate = $null
        $driverVersion = $null
        if ($values[5] -match '^(\S+)\s+(\d+(?:\.\d+){1,3})$') {
            $driverVersion = $Matches[2]
            $date = [datetime]::MinValue
            if ([datetime]::TryParseExact($Matches[1], [string[]]@('MM/dd/yyyy', 'dd.MM.yyyy', 'yyyy-MM-dd'), $inv, 'None', [ref]$date)) {
                $driverDate = $date.ToString('yyyy-MM-dd', $inv)
            }
        }
        $packages.Add([ordered]@{
                publishedName = $values[0]
                originalName  = $values[1]
                provider      = $values[2]
                className     = $values[3]
                classGuid     = $values[4].ToLowerInvariant()
                driverDate    = $driverDate
                driverVersion = $driverVersion
                signer        = $values[6]
            })
    }
    [pscustomobject]@{ Packages = $packages.ToArray(); Raw = ($rawBlocks -join "`r`n`r`n"); Unparsed = $unparsed }
}

function Group-ByAdapterName {
    param([object[]] $Items)
    $map = @{}
    foreach ($item in $Items) {
        if (-not $map.ContainsKey($item.Name)) { $map[$item.Name] = New-Object System.Collections.Generic.List[object] }
        $map[$item.Name].Add($item)
    }
    $map
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'adapters' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)

    $netAdapters = Invoke-Source -Context $ctx -Source 'Get-NetAdapter' -AsList -ScriptBlock {
        Get-NetAdapter -IncludeHidden -ErrorAction Stop
    }

    $bindings = Invoke-Source -Context $ctx -Source 'Get-NetAdapterBinding' -AsList -ScriptBlock {
        Get-NetAdapterBinding -IncludeHidden -AllBindings
    }
    $advanced = Invoke-Source -Context $ctx -Source 'Get-NetAdapterAdvancedProperty' -AsList -ScriptBlock {
        Get-NetAdapterAdvancedProperty -IncludeHidden -AllProperties
    }
    $signed = Invoke-Source -Context $ctx -Source 'Win32_PnPSignedDriver' -AsList -ScriptBlock {
        Get-CimInstance -ClassName Win32_PnPSignedDriver -Filter "DeviceClass='NET'" -ErrorAction Stop
    }

    $bindingsByName = if ($null -ne $bindings) { Group-ByAdapterName $bindings } else { $null }
    $advancedByName = if ($null -ne $advanced) { Group-ByAdapterName $advanced } else { $null }
    $signedById = $null
    if ($null -ne $signed) {
        $signedById = @{}
        foreach ($s in $signed) { if ($s.DeviceID) { $signedById[$s.DeviceID] = $s } }
    }

    $adapters = $null
    if ($null -ne $netAdapters) {
        $adapters = @($netAdapters | Sort-Object InterfaceIndex | ForEach-Object {
                $a = $_
                $sd = if ($null -ne $signedById -and $a.PnPDeviceID) { $signedById[$a.PnPDeviceID] } else { $null }

                $driverDate = if ($a.DriverDate) { $a.DriverDate } elseif ($sd -and $sd.DriverDate) {
                    $sd.DriverDate.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
                } else { $null }

                # Plain assignment, not "$x = if ...": an if-expression unrolls
                # arrays, turning @() into $null and a 1-item array into a scalar.
                $adapterBindings = $null
                if ($null -ne $bindingsByName) {
                    $adapterBindings = @(if ($bindingsByName.ContainsKey($a.Name)) {
                            $bindingsByName[$a.Name] | Sort-Object ComponentID | ForEach-Object {
                                [ordered]@{ componentId = $_.ComponentID; displayName = $_.DisplayName; enabled = [bool]$_.Enabled }
                            }
                        })
                }
                $adapterAdvanced = $null
                if ($null -ne $advancedByName) {
                    $adapterAdvanced = @(if ($advancedByName.ContainsKey($a.Name)) {
                            $advancedByName[$a.Name] | Sort-Object RegistryKeyword | ForEach-Object {
                                [ordered]@{
                                    keyword       = $_.RegistryKeyword
                                    displayName   = $_.DisplayName
                                    displayValue  = $_.DisplayValue
                                    registryValue = @($_.RegistryValue | ForEach-Object { [string]$_ })
                                }
                            }
                        })
                }

                [ordered]@{
                    name                 = $a.Name
                    interfaceDescription = $a.InterfaceDescription
                    interfaceIndex       = [int]$a.InterfaceIndex
                    interfaceGuid        = if ($a.InterfaceGuid) { ([string]$a.InterfaceGuid).ToLowerInvariant() } else { $null }
                    macAddress           = if ($a.MacAddress) { $a.MacAddress } else { $null }
                    status               = $a.Status
                    adminStatus          = $a.AdminStatus
                    mediaConnectionState = $a.MediaConnectionState
                    virtual              = [bool]$a.Virtual
                    hidden               = [bool]$a.Hidden
                    hardwareInterface    = [bool]$a.HardwareInterface
                    connectorPresent     = [bool]$a.ConnectorPresent
                    endpointInterface    = [bool]$a.EndpointInterface
                    componentId          = if ($a.ComponentID) { $a.ComponentID } else { $null }
                    pnpDeviceId          = if ($a.PnPDeviceID) { $a.PnPDeviceID } else { $null }
                    mediaType            = if ($a.MediaType) { $a.MediaType } else { $null }
                    physicalMediaType    = if ($a.PhysicalMediaType) { $a.PhysicalMediaType } else { $null }
                    ndisPhysicalMedium   = $a.NdisPhysicalMedium
                    mtuSize              = $a.MtuSize
                    receiveLinkSpeedBps  = $a.ReceiveLinkSpeed
                    transmitLinkSpeedBps = $a.TransmitLinkSpeed
                    driver               = [ordered]@{
                        provider    = if ($a.DriverProvider) { $a.DriverProvider } elseif ($sd) { $sd.DriverProviderName } else { $null }
                        version     = if ($a.DriverVersionString) { $a.DriverVersionString } elseif ($sd) { $sd.DriverVersion } else { $null }
                        date        = $driverDate
                        description = if ($a.DriverDescription) { $a.DriverDescription } else { $null }
                        fileName    = if ($a.DriverFileName) { $a.DriverFileName } else { $null }
                        ndisVersion = if ($a.NdisVersion) { $a.NdisVersion } else { $null }
                        infName     = if ($sd) { $sd.InfName } else { $null }
                        isSigned    = if ($sd) { [bool]$sd.IsSigned } else { $null }
                        signer      = if ($sd) { $sd.Signer } else { $null }
                    }
                    bindings             = $adapterBindings
                    advancedProperties   = $adapterAdvanced
                }
            })
    }

    $devices = Invoke-Source -Context $ctx -Source 'Get-PnpDevice' -AsList -ScriptBlock {
        Get-PnpDevice -Class Net -ErrorAction Stop | Sort-Object InstanceId | ForEach-Object {
            [ordered]@{
                instanceId   = $_.InstanceId
                friendlyName = $_.FriendlyName
                manufacturer = $_.Manufacturer
                status       = $_.Status
                present      = [bool]$_.Present
                problem      = $_.Problem
                problemCode  = $_.ConfigManagerErrorCode
            }
        }
    }

    $driverPackages = $null
    $driverPackagesRaw = $null
    $pnputil = Invoke-NativeCommand -Context $ctx -Source 'pnputil /enum-drivers' `
        -FilePath (Join-Path $env:SystemRoot 'System32\pnputil.exe') -ArgumentList '/enum-drivers'
    if ($null -ne $pnputil -and $pnputil.exitCode -eq 0) {
        $parsed = ConvertFrom-PnputilDrivers -Text $pnputil.stdout
        $driverPackages = $parsed.Packages
        $driverPackagesRaw = $parsed.Raw
        if ($parsed.Unparsed -gt 0) {
            Add-CollectorError -Context $ctx -Source 'pnputil /enum-drivers' -Kind Exception `
                -Message "$($parsed.Unparsed) Net-class block(s) in an unrecognized format; see driverPackagesRaw."
        }
    }

    [ordered]@{
        adapters          = $adapters
        devices           = $devices
        driverPackages    = $driverPackages
        driverPackagesRaw = $driverPackagesRaw
    }
}
