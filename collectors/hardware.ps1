# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'hardware': CPU, system, memory modules and slots, motherboard,
# BIOS, GPUs, physical disks (type, bus, health; SMART counters with admin
# rights) and expansion slots - the facts for bottlenecks and upgrade options.
# Serial numbers and UUIDs are not collected. Network cards: see 'adapters'.
# Schema: docs/schema/hardware.md. Read-only.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

$DisplayClassKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
$ArchitectureNames = @{ 0 = 'x86'; 5 = 'ARM'; 6 = 'ia64'; 9 = 'x64'; 12 = 'ARM64' }
$PcSystemTypeNames = @{ 0 = 'Unspecified'; 1 = 'Desktop'; 2 = 'Mobile'; 3 = 'Workstation'; 4 = 'EnterpriseServer'; 5 = 'SOHOServer'; 6 = 'AppliancePC'; 7 = 'PerformanceServer'; 8 = 'Slate' }
# SMBIOS type 17 memory types.
$MemoryTypeNames = @{
    18 = 'DDR'; 19 = 'DDR2'; 20 = 'DDR'; 21 = 'DDR2'; 22 = 'DDR2 FB-DIMM'; 24 = 'DDR3'; 26 = 'DDR4'
    27 = 'LPDDR'; 28 = 'LPDDR2'; 29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5'
}
$FormFactorNames = @{ 8 = 'DIMM'; 12 = 'SODIMM'; 13 = 'SRIMM'; 0 = 'Unknown'; 1 = 'Other' }
$SlotUsageNames = @{ 1 = 'Other'; 2 = 'Unknown'; 3 = 'Available'; 4 = 'InUse' }

function Get-Name {
    # Name from a lookup table, or the raw value as a string if unknown.
    param([hashtable] $Table, $Value)
    if ($null -eq $Value) { return $null }
    if ($Table.ContainsKey([int]$Value)) { return $Table[[int]$Value] }
    [string]$Value
}

function ConvertTo-CleanString {
    # Trims and turns empty and placeholder values (SMBIOS fills unknown
    # fields with 'Unknown', 'To Be Filled By O.E.M.', 'x.x', ...) into $null.
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim()
    if ($s -eq '' -or $s -match '^(Unknown|Undefined|None|Default string|To Be Filled By O\.E\.M\.|System (Product Name|manufacturer|Version)|Not Specified|x\.x|0+)$') { return $null }
    $s
}

function Get-PciIds {
    # Vendor and device IDs from a PnP device ID; the instance part after the
    # last backslash is machine-specific and is not returned.
    param($PnpDeviceId)
    if ($null -eq $PnpDeviceId -or [string]$PnpDeviceId -notmatch 'VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})') { return @{ vendorId = $null; deviceId = $null } }
    @{ vendorId = $Matches[1].ToUpperInvariant(); deviceId = $Matches[2].ToUpperInvariant() }
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'hardware' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)

    $cpus = Invoke-Source -Context $ctx -Source 'Win32_Processor' -AsList -ScriptBlock {
        Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                name                          = ConvertTo-CleanString $_.Name
                manufacturer                  = ConvertTo-CleanString $_.Manufacturer
                cores                         = $_.NumberOfCores
                logicalProcessors             = $_.NumberOfLogicalProcessors
                maxClockMhz                   = $_.MaxClockSpeed
                socket                        = ConvertTo-CleanString $_.SocketDesignation
                l2CacheKb                     = $_.L2CacheSize
                l3CacheKb                     = $_.L3CacheSize
                architecture                  = Get-Name $ArchitectureNames $_.Architecture
                virtualizationFirmwareEnabled = $_.VirtualizationFirmwareEnabled
            }
        }
    }

    $system = Invoke-Source -Context $ctx -Source 'Win32_ComputerSystem' -ScriptBlock {
        $c = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        [ordered]@{
            manufacturer             = ConvertTo-CleanString $c.Manufacturer
            model                    = ConvertTo-CleanString $c.Model
            pcSystemType             = Get-Name $PcSystemTypeNames $c.PCSystemType
            systemType               = $c.SystemType
            totalPhysicalMemoryBytes = $c.TotalPhysicalMemory
        }
    }

    # Part numbers identify the module model, not the machine; serial numbers
    # are not read.
    $modules = Invoke-Source -Context $ctx -Source 'Win32_PhysicalMemory' -AsList -ScriptBlock {
        Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop | Sort-Object BankLabel, DeviceLocator | ForEach-Object {
            [ordered]@{
                bankLabel          = ConvertTo-CleanString $_.BankLabel
                deviceLocator      = ConvertTo-CleanString $_.DeviceLocator
                capacityBytes      = $_.Capacity
                speedMts           = $_.Speed
                configuredSpeedMts = $_.ConfiguredClockSpeed
                type               = Get-Name $MemoryTypeNames $_.SMBIOSMemoryType
                formFactor         = Get-Name $FormFactorNames $_.FormFactor
                manufacturer       = ConvertTo-CleanString $_.Manufacturer
                partNumber         = ConvertTo-CleanString $_.PartNumber
            }
        }
    }
    $arrays = Invoke-Source -Context $ctx -Source 'Win32_PhysicalMemoryArray' -AsList -ScriptBlock {
        # Use 3 = system memory; other arrays are flash or video memory.
        Get-CimInstance -ClassName Win32_PhysicalMemoryArray -ErrorAction Stop | Where-Object { $_.Use -eq 3 } | ForEach-Object {
            $maxKb = if ($_.MaxCapacityEx) { [int64]$_.MaxCapacityEx } else { [int64]$_.MaxCapacity }
            [ordered]@{
                maxCapacityBytes = if ($maxKb -gt 0) { $maxKb * 1024 } else { $null }
                slots            = $_.MemoryDevices
            }
        }
    }

    $board = Invoke-Source -Context $ctx -Source 'Win32_BaseBoard' -ScriptBlock {
        $b = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop | Select-Object -First 1
        [ordered]@{
            manufacturer = ConvertTo-CleanString $b.Manufacturer
            product      = ConvertTo-CleanString $b.Product
            version      = ConvertTo-CleanString $b.Version
        }
    }
    $bios = Invoke-Source -Context $ctx -Source 'Win32_BIOS' -ScriptBlock {
        $b = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop | Select-Object -First 1
        [ordered]@{
            manufacturer  = ConvertTo-CleanString $b.Manufacturer
            version       = ConvertTo-CleanString $b.SMBIOSBIOSVersion
            releaseDate   = if ($b.ReleaseDate) { $b.ReleaseDate.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } else { $null }
            smbiosVersion = if ($null -ne $b.SMBIOSMajorVersion) { '{0}.{1}' -f $b.SMBIOSMajorVersion, $b.SMBIOSMinorVersion } else { $null }
        }
    }

    # AdapterRAM is a 32-bit field and stops at 4 GB; the driver writes the
    # real size to HardwareInformation.qwMemorySize in the display class key.
    $videoMemory = @{}
    # Subkeys are opened one by one: the class key also has a 'Properties'
    # subkey that a normal user may not open, which fails Get-ChildItem.
    $null = Invoke-Source -Context $ctx -Source 'display class' -AsList -ScriptBlock {
        $class = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($DisplayClassKey.Substring(6))
        if ($null -eq $class) { return }
        try {
            foreach ($name in ($class.GetSubKeyNames() | Where-Object { $_ -match '^\d{4}$' })) {
                $item = $null
                try { $item = $class.OpenSubKey($name) } catch { continue }
                if ($null -eq $item) { continue }
                try {
                    $desc = $item.GetValue('DriverDesc', $null)
                    $size = $item.GetValue('HardwareInformation.qwMemorySize', $null)
                    if ($null -eq $size) {
                        $raw = $item.GetValue('HardwareInformation.MemorySize', $null)
                        if ($raw -is [byte[]] -and $raw.Length -ge 4) { $size = [BitConverter]::ToUInt32($raw, 0) } elseif ($raw -is [int]) { $size = [uint32]$raw }
                    }
                    if ($desc -and $null -ne $size) { $videoMemory[[string]$desc] = [int64]$size }
                }
                finally { $item.Close() }
            }
        }
        finally { $class.Close() }
    }
    $gpus = Invoke-Source -Context $ctx -Source 'Win32_VideoController' -AsList -ScriptBlock {
        Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | ForEach-Object {
            $ids = Get-PciIds $_.PNPDeviceID
            $name = ConvertTo-CleanString $_.Name
            $memory = $null
            $source = $null
            if ($name -and $videoMemory.ContainsKey($name)) { $memory = $videoMemory[$name]; $source = 'registry' }
            elseif ($_.AdapterRAM) { $memory = [int64]$_.AdapterRAM; $source = 'cim' }
            [ordered]@{
                name          = $name
                vendorId      = $ids.vendorId
                deviceId      = $ids.deviceId
                memoryBytes   = $memory
                memorySource  = $source
                driverVersion = ConvertTo-CleanString $_.DriverVersion
                driverDate    = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } else { $null }
            }
        }
    }

    # The disk of the Windows partition: "HDD as the system disk" is a bottleneck.
    $systemDisk = $null
    $systemDiskNumber = Invoke-Source -Context $ctx -Source 'Get-Partition' -ScriptBlock {
        (Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':') -ErrorAction Stop | Select-Object -First 1).DiskNumber
    }
    if ($null -ne $systemDiskNumber) { $systemDisk = [string]$systemDiskNumber }

    # SMART-like counters need admin rights.
    $reliability = @{}
    $null = Invoke-Source -Context $ctx -Source 'Get-StorageReliabilityCounter' -AsList -RequiresAdmin -ScriptBlock {
        foreach ($d in (Get-PhysicalDisk -ErrorAction Stop)) {
            $r = $d | Get-StorageReliabilityCounter -ErrorAction Stop
            if ($null -ne $r) {
                $reliability[[string]$d.DeviceId] = [ordered]@{
                    temperatureC     = $r.Temperature
                    temperatureMaxC  = $r.TemperatureMax
                    wearPercent      = $r.Wear
                    powerOnHours     = $r.PowerOnHours
                    readErrorsTotal  = $r.ReadErrorsTotal
                    writeErrorsTotal = $r.WriteErrorsTotal
                }
            }
        }
    }
    $disks = Invoke-Source -Context $ctx -Source 'Get-PhysicalDisk' -AsList -ScriptBlock {
        Get-PhysicalDisk -ErrorAction Stop | Sort-Object { [int]$_.DeviceId } | ForEach-Object {
            $id = [string]$_.DeviceId
            [ordered]@{
                deviceId          = $id
                friendlyName      = ConvertTo-CleanString $_.FriendlyName
                mediaType         = [string]$_.MediaType
                busType           = [string]$_.BusType
                sizeBytes         = $_.Size
                spindleSpeed      = $_.SpindleSpeed
                healthStatus      = [string]$_.HealthStatus
                operationalStatus = @($_.OperationalStatus | ForEach-Object { [string]$_ })
                firmwareVersion   = ConvertTo-CleanString $_.FirmwareVersion
                isSystem          = if ($null -ne $systemDisk) { $id -eq $systemDisk } else { $null }
                reliability       = if ($reliability.ContainsKey($id)) { $reliability[$id] } else { $null }
            }
        }
    }

    $slots = Invoke-Source -Context $ctx -Source 'Win32_SystemSlot' -AsList -ScriptBlock {
        Get-CimInstance -ClassName Win32_SystemSlot -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                designation  = ConvertTo-CleanString $_.SlotDesignation
                usage        = Get-Name $SlotUsageNames $_.CurrentUsage
                maxDataWidth = $_.MaxDataWidth
            }
        }
    }

    [ordered]@{
        system   = $system
        cpus     = $cpus
        memory   = [ordered]@{
            modules = $modules
            arrays  = $arrays
        }
        board    = $board
        bios     = $bios
        gpus     = $gpus
        disks    = $disks
        slots    = $slots
    }
}
