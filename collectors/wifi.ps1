# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'wifi': Wi-Fi interfaces (signal, channel, band, radio type,
# link rates), driver capabilities and the neighbouring access points of the
# last scan without their names and addresses.
# Schema: docs/schema/wifi.md. Read-only; no admin rights required. Windows 11
# 24H2+ needs the location permission for WLAN data.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

# netsh labels and many values are localized, and the set of lines differs
# between Windows versions. Fields are recognized by the shape of the value;
# only 'SSID', 'BSSID' and 'Rssi' labels are the same in every language.
$GuidPattern = '^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$'
$MacPattern = '([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
$BandPattern = '^(2[.,]4|5|6)\s*\p{L}+'
$LocationMarker = 'privacy-location'

function Get-NetshPairs {
    # "label : value" lines of a block, in order: @{ label; value }. Labels
    # that wrap onto the next line leave a line without a colon; it is skipped
    # (the value is on the line with the colon).
    param([AllowEmptyString()][string] $Text)
    , @(foreach ($line in ($Text -split '\r?\n')) {
            $i = $line.IndexOf(':')
            if ($i -lt 0) { continue }
            [ordered]@{ label = $line.Substring(0, $i).Trim(); value = $line.Substring($i + 1).Trim() }
        })
}

function ConvertTo-BandGHz {
    # "2,4 GHz" / "5 GHz" / "6 GHz" -> '2.4' / '5' / '6'; anything else -> $null.
    param($Value)
    if ($null -eq $Value -or [string]$Value -notmatch $BandPattern) { return $null }
    $Matches[1] -replace ',', '.'
}

function ConvertTo-Number {
    param($Value)
    if ($null -eq $Value -or [string]$Value -notmatch '^\d+([.,]\d+)?$') { return $null }
    [double]::Parse(([string]$Value -replace ',', '.'), [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-WlanInterfaces {
    # Parses 'netsh wlan show interfaces'. Returns @{ Interfaces; Bssids }:
    # BSSIDs of the connected access points are returned separately, for
    # matching against the scan only; they do not go into the snapshot.
    param([AllowEmptyString()][string] $Text)
    $interfaces = [System.Collections.Generic.List[object]]::new()
    $bssids = [System.Collections.Generic.List[string]]::new()
    foreach ($block in ($Text -split '\r?\n\s*\r?\n')) {
        $pairs = Get-NetshPairs $block
        $guidIndex = -1
        for ($i = 0; $i -lt $pairs.Count; $i++) { if ($pairs[$i].value -match $GuidPattern) { $guidIndex = $i; break } }
        if ($guidIndex -lt 0 -or $pairs.Count -lt 2) { continue }

        $find = { param($test) for ($j = 0; $j -lt $pairs.Count; $j++) { if (& $test $pairs[$j]) { return $j } }; -1 }
        $ssidIndex = & $find { param($p) $p.label -eq 'SSID' }
        $bssidIndex = & $find { param($p) $p.label -match 'BSSID' }
        $signalIndex = & $find { param($p) $p.value -match '^\d{1,3}\s*%$' }
        $radioIndex = & $find { param($p) $p.value -match '^802\.11\w+$' }
        $bandIndex = & $find { param($p) $null -ne (ConvertTo-BandGHz $p.value) }
        $rssiIndex = & $find { param($p) $p.label -eq 'Rssi' }

        # Channel: the first whole number after the BSSID line (Windows 10
        # prints it after "Connection mode", Windows 11 right after "Band").
        $channel = $null
        if ($bssidIndex -ge 0) {
            $end = if ($signalIndex -ge 0) { $signalIndex - 2 } else { $pairs.Count }
            for ($j = $bssidIndex + 1; $j -lt $end; $j++) {
                if ($pairs[$j].value -match '^\d{1,3}$') { $channel = [int]$pairs[$j].value; break }
            }
        }
        $receive = $null; $transmit = $null
        if ($signalIndex -ge 2) {
            $receive = ConvertTo-Number $pairs[$signalIndex - 2].value
            $transmit = ConvertTo-Number $pairs[$signalIndex - 1].value
        }
        if ($bssidIndex -ge 0 -and $pairs[$bssidIndex].value -match $MacPattern) { $bssids.Add(($Matches[0].ToLowerInvariant() -replace '-', ':')) }

        $guid = $pairs[$guidIndex].value.Trim('{}').ToLowerInvariant()
        $interfaces.Add([ordered]@{
                name                 = $pairs[0].value
                description          = $pairs[1].value
                interfaceGuid        = '{' + $guid + '}'
                connected            = ($ssidIndex -ge 0)
                ssid                 = if ($ssidIndex -ge 0 -and $pairs[$ssidIndex].value) { $pairs[$ssidIndex].value } else { $null }
                bandGHz              = if ($bandIndex -ge 0) { ConvertTo-BandGHz $pairs[$bandIndex].value } else { $null }
                channel              = $channel
                radioType            = if ($radioIndex -ge 0) { $pairs[$radioIndex].value } else { $null }
                authentication       = if ($radioIndex -ge 0 -and $radioIndex + 1 -lt $pairs.Count) { $pairs[$radioIndex + 1].value } else { $null }
                cipher               = if ($radioIndex -ge 0 -and $radioIndex + 2 -lt $pairs.Count) { $pairs[$radioIndex + 2].value } else { $null }
                receiveRateMbps      = $receive
                transmitRateMbps     = $transmit
                signalPercent        = if ($signalIndex -ge 0 -and $pairs[$signalIndex].value -match '^(\d{1,3})') { [int]$Matches[1] } else { $null }
                rssiDbm              = if ($rssiIndex -ge 0 -and $pairs[$rssiIndex].value -match '^-?\d+$') { [int]$pairs[$rssiIndex].value } else { $null }
            })
    }
    [pscustomobject]@{ Interfaces = $interfaces.ToArray(); Bssids = $bssids.ToArray() }
}

function ConvertFrom-WlanDrivers {
    # Parses 'netsh wlan show drivers': one block per interface, started by a
    # non-indented "Interface name: <alias>" line.
    param([AllowEmptyString()][string] $Text)
    $blocks = [System.Collections.Generic.List[object]]::new()
    $current = $null
    foreach ($line in ($Text -split '\r?\n')) {
        if ($line -match '^\S[^:]*:\s*(.+?)\s*$') {
            $current = @{ name = $Matches[1]; lines = [System.Collections.Generic.List[string]]::new() }
            $blocks.Add($current)
            continue
        }
        if ($null -ne $current) { $current.lines.Add($line) }
    }
    , @(foreach ($b in $blocks) {
            $body = $b.lines -join "`n"
            $pairs = Get-NetshPairs $body
            if ($pairs.Count -lt 4) { continue }
            # A date such as 03.03.2026 also looks like a dotted version, so
            # dates are taken out first.
            $versionValue = $null
            $dateValue = $null
            foreach ($p in $pairs) {
                if ($null -eq $dateValue -and $p.value -match '^\d{1,2}[./]\d{1,2}[./]\d{4}$') { $dateValue = $p.value; continue }
                if ($null -eq $versionValue -and $p.value -match '^\d+(\.\d+){1,3}$') { $versionValue = $p.value }
            }
            $driverDate = $null
            if ($null -ne $dateValue) {
                $parsed = [datetime]::MinValue
                $inv = [Globalization.CultureInfo]::InvariantCulture
                # Day-first with dots (ru, de, ...), month-first with slashes (en-US).
                if ([datetime]::TryParseExact($dateValue, [string[]]@('dd.MM.yyyy', 'd.M.yyyy', 'M/d/yyyy', 'MM/dd/yyyy'), $inv, 'None', [ref]$parsed)) {
                    $driverDate = $parsed.ToString('yyyy-MM-dd', $inv)
                }
            }
            $radioTypes = $null
            foreach ($p in $pairs) {
                if ($p.value -match '^802\.11\w+(\s+802\.11\w+)*$') { $radioTypes = @($p.value -split '\s+'); break }
            }
            $bands = $null
            $found = @(foreach ($line in $b.lines) {
                    if ($line -match '^\s*(2[.,]4|5|6)\s*\p{L}+\s*\[') { ConvertTo-BandGHz $line.Trim() }
                })
            if ($found.Count) { $bands = $found }
            [ordered]@{
                interfaceName       = $b.name
                driver              = $pairs[0].value
                vendor              = $pairs[1].value
                provider            = $pairs[2].value
                version             = $versionValue
                date                = $driverDate
                radioTypesSupported = $radioTypes
                bandsSupportedGHz   = $bands
                wpa3Supported       = [bool]($body -match 'WPA3')
            }
        })
}

function ConvertFrom-WlanNetworks {
    # Parses 'netsh wlan show networks mode=bssid' (the last scan, no new scan
    # is started). Returns @{ networkCount; bss[] } without SSIDs and BSSIDs:
    # names and addresses of neighbouring networks point to a place.
    param([AllowEmptyString()][string] $Text, [string[]] $ConnectedBssids = @())
    $networkCount = 0
    $list = [System.Collections.Generic.List[object]]::new()
    $current = $null
    $pairs = $null
    $flush = {
        if ($null -eq $current) { return }
        $signalIndex = -1
        for ($j = 0; $j -lt $pairs.Count; $j++) { if ($pairs[$j].value -match '^\d{1,3}\s*%$') { $signalIndex = $j; break } }
        $channel = $null; $utilization = $null; $stations = $null
        for ($j = [Math]::Max(0, $signalIndex + 1); $j -lt $pairs.Count; $j++) {
            if ($null -eq $channel -and $pairs[$j].value -match '^\d{1,3}$') { $channel = [int]$pairs[$j].value }
            if ($pairs[$j].value -match '^\d+\s*\((\d{1,3})\s*%\)$') {
                $utilization = [int]$Matches[1]
                if ($j -gt 0 -and $pairs[$j - 1].value -match '^\d+$') { $stations = [int]$pairs[$j - 1].value }
            }
        }
        $radio = @($pairs | Where-Object { $_.value -match '^802\.11\w+$' } | Select-Object -First 1)
        $band = @($pairs | ForEach-Object { ConvertTo-BandGHz $_.value } | Where-Object { $_ } | Select-Object -First 1)
        $list.Add([ordered]@{
                connected                 = ($ConnectedBssids -contains $current)
                bandGHz                   = if ($band.Count) { $band[0] } else { $null }
                channel                   = $channel
                signalPercent             = if ($signalIndex -ge 0 -and $pairs[$signalIndex].value -match '^(\d{1,3})') { [int]$Matches[1] } else { $null }
                radioType                 = if ($radio.Count) { $radio[0].value } else { $null }
                channelUtilizationPercent = $utilization
                connectedStations         = $stations
            })
    }
    foreach ($line in ($Text -split '\r?\n')) {
        if ($line -match '^SSID \d+\s*:') {
            . $flush
            $current = $null
            $networkCount++
            continue
        }
        if ($line -match ('^\s+BSSID \d+\s*:\s*(' + $MacPattern + ')')) {
            . $flush
            $current = $Matches[1].ToLowerInvariant() -replace '-', ':'
            $pairs = [System.Collections.Generic.List[object]]::new()
            continue
        }
        if ($null -ne $current) {
            foreach ($p in (Get-NetshPairs $line)) { $pairs.Add($p) }
        }
    }
    . $flush
    [ordered]@{
        networkCount = $networkCount
        bss          = @($list | Sort-Object { $_['bandGHz'] }, { $_['channel'] }, { - $_['signalPercent'] })
    }
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'wifi' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)

    $service = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
    if ($null -eq $service) { return (New-SkipResult 'The WLAN AutoConfig service (WlanSvc) is not installed: no Wi-Fi on this system.') }
    if ($service.Status -ne 'Running') { return (New-SkipResult 'The WLAN AutoConfig service (WlanSvc) is not running: Wi-Fi is not in use.') }

    $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
    # Exit code 1 is checked here, not by Invoke-NativeCommand: without the
    # location permission netsh fails with a message that names the privacy
    # settings page, and that case is AccessDenied, not an exception.
    $run = {
        param([string] $Source, [string[]] $Arguments)
        $r = Invoke-NativeCommand -Context $ctx -Source $Source -FilePath $netsh -ArgumentList $Arguments -SuccessExitCodes @(0, 1)
        if ($null -eq $r) { return $null }
        if (($r.stdout + $r.stderr) -match $LocationMarker) {
            Add-CollectorError -Context $ctx -Source $Source -Kind AccessDenied -Message 'Windows requires the location permission for WLAN data (Settings > Privacy & security > Location).'
            return $null
        }
        if ($r.exitCode -ne 0) {
            $detail = @(($r.stderr + "`n" + $r.stdout) -split '\r?\n' | Where-Object { $_.Trim() } | Select-Object -First 1)
            Add-CollectorError -Context $ctx -Source $Source -Kind Exception -Message ("Exit code {0}. {1}" -f $r.exitCode, ($detail -join '')).Trim()
            return $null
        }
        $r
    }

    $interfacesRaw = & $run 'netsh wlan show interfaces' @('wlan', 'show', 'interfaces')
    $parsedInterfaces = $null
    if ($null -ne $interfacesRaw) {
        $parsedInterfaces = ConvertFrom-WlanInterfaces $interfacesRaw.stdout
        if ($parsedInterfaces.Interfaces.Count -eq 0) {
            return (New-SkipResult 'No Wi-Fi interface on this system.')
        }
    }

    $driversRaw = & $run 'netsh wlan show drivers' @('wlan', 'show', 'drivers')
    $drivers = $null
    if ($null -ne $driversRaw) { $drivers = ConvertFrom-WlanDrivers $driversRaw.stdout }

    $neighbors = $null
    $networksRaw = & $run 'netsh wlan show networks' @('wlan', 'show', 'networks', 'mode=bssid')
    if ($null -ne $networksRaw) {
        $own = if ($null -ne $parsedInterfaces) { $parsedInterfaces.Bssids } else { @() }
        $neighbors = ConvertFrom-WlanNetworks -Text $networksRaw.stdout -ConnectedBssids $own
    }

    if ($null -eq $parsedInterfaces -and $null -eq $drivers -and $null -eq $neighbors) { return $null }
    # Plain assignment, not "x = if ...": an if-expression unrolls a 1-item array.
    $interfaces = $null
    if ($null -ne $parsedInterfaces) { $interfaces = $parsedInterfaces.Interfaces }
    [ordered]@{
        interfaces = $interfaces
        drivers    = $drivers
        neighbors  = $neighbors
    }
}
