# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'system': Windows version and build, computer identity, boot and
# uptime, pending reboot, installed updates, network connection profiles.
# Schema: docs/schema/system.md. Read-only; no admin rights required.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

function ConvertTo-HotfixDate {
    # Win32_QuickFixEngineering.InstalledOn is a string: usually M/d/yyyy,
    # on some old systems a hex FILETIME. Returns yyyy-MM-dd or $null.
    param([AllowNull()][string] $Value)
    if (-not $Value) { return $null }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $date = [datetime]::MinValue
    if ([datetime]::TryParseExact($Value, [string[]]@('M/d/yyyy', 'MM/dd/yyyy', 'yyyyMMdd'), $inv, 'None', [ref]$date)) {
        return $date.ToString('yyyy-MM-dd', $inv)
    }
    if ($Value -match '^[0-9a-fA-F]{15,16}$') {
        try { return [datetime]::FromFileTime([Convert]::ToInt64($Value, 16)).ToString('yyyy-MM-dd', $inv) } catch { }
    }
    $null
}

function Get-ProcessorArchitecture {
    $arch = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name 'PROCESSOR_ARCHITECTURE'
    switch ($arch) {
        'AMD64' { 'x64' }
        'ARM64' { 'arm64' }
        'x86' { 'x86' }
        default { $arch }
    }
}

Invoke-Collector -Module 'system' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)

    $cvPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $os = Invoke-Source -Context $ctx -Source 'Win32_OperatingSystem' -ScriptBlock {
        $cim = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $build = [int](Get-RegistryValue $cvPath 'CurrentBuild')
        $osLanguage = $null
        try { $osLanguage = ([Globalization.CultureInfo]::new([int]$cim.OSLanguage)).Name } catch { }
        [ordered]@{
            caption          = $cim.Caption
            # ProductName still says "Windows 10" on Windows 11; family is derived from the build.
            productName      = Get-RegistryValue $cvPath 'ProductName'
            family           = if ($build -ge 22000) { 'Windows 11' } elseif ($build -ge 10240) { 'Windows 10' } else { $null }
            editionId        = Get-RegistryValue $cvPath 'EditionID'
            displayVersion   = Get-RegistryValue $cvPath 'DisplayVersion'
            version          = $cim.Version
            build            = $build
            ubr              = Get-RegistryValue $cvPath 'UBR'
            architecture     = Get-ProcessorArchitecture
            installationType = Get-RegistryValue $cvPath 'InstallationType'
            installDate      = $cim.InstallDate
            osLanguage       = $osLanguage
            uiLanguage       = (Get-UICulture).Name
        }
    }

    $computer = Invoke-Source -Context $ctx -Source 'Win32_ComputerSystem' -ScriptBlock {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        [ordered]@{
            name         = $env:COMPUTERNAME
            partOfDomain = [bool]$cs.PartOfDomain
            domain       = if ($cs.PartOfDomain) { $cs.Domain } else { $null }
            workgroup    = if ($cs.PartOfDomain) { $null } else { $cs.Workgroup }
            timeZone     = (Get-TimeZone).Id
        }
    }

    $boot = Invoke-Source -Context $ctx -Source 'boot' -ScriptBlock {
        $cim = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $hiberboot = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled'
        [ordered]@{
            lastBootUpTime     = $cim.LastBootUpTime
            uptimeSec          = [int64]([datetime]::Now - $cim.LastBootUpTime).TotalSeconds
            # With fast startup a shutdown is a hibernate: uptime and driver state survive it.
            fastStartupEnabled = if ($null -eq $hiberboot) { $null } else { [int]$hiberboot -eq 1 }
        }
    }

    $pendingReboot = Invoke-Source -Context $ctx -Source 'pendingReboot' -ScriptBlock {
        $renames = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
        [ordered]@{
            componentServicing   = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
            windowsUpdate        = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
            fileRenameOperations = $null -ne $renames -and @($renames).Count -gt 0
        }
    }

    $hotfixes = Invoke-Source -Context $ctx -Source 'Win32_QuickFixEngineering' -AsList -ScriptBlock {
        Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop |
            ForEach-Object {
                $raw = $_.CimInstanceProperties['InstalledOn'].Value
                [ordered]@{
                    id             = $_.HotFixID
                    description    = $_.Description
                    installedOn    = ConvertTo-HotfixDate $raw
                    installedOnRaw = $raw
                }
            } |
            Sort-Object -Property @{ Expression = { $_.installedOn }; Descending = $true }, @{ Expression = { $_.id } }
    }

    $profiles = Invoke-Source -Context $ctx -Source 'Get-NetConnectionProfile' -AsList -ScriptBlock {
        # With no connected network the cmdlet throws ObjectNotFound: that is an empty list, not an error.
        $items = try { Get-NetConnectionProfile -ErrorAction Stop }
        catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }
        $items | ForEach-Object {
            [ordered]@{
                name                     = $_.Name
                interfaceAlias           = $_.InterfaceAlias
                interfaceIndex           = $_.InterfaceIndex
                category                 = $_.NetworkCategory
                ipv4Connectivity         = $_.IPv4Connectivity
                ipv6Connectivity         = $_.IPv6Connectivity
                domainAuthenticationKind = $_.DomainAuthenticationKind
            }
        }
    }

    [ordered]@{
        os              = $os
        computer        = $computer
        boot            = $boot
        pendingReboot   = $pendingReboot
        hotfixes        = $hotfixes
        networkProfiles = $profiles
    }
}
