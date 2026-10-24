# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/hardware.ps1: helpers on known input and the
# collector against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\hardware.ps1'

Describe 'hardware helpers' {
    . $collector

    It 'maps codes to names and keeps unknown codes as strings' {
        Get-Name $MemoryTypeNames 26 | Should Be 'DDR4'
        Get-Name $MemoryTypeNames 34 | Should Be 'DDR5'
        Get-Name $FormFactorNames 12 | Should Be 'SODIMM'
        Get-Name $PcSystemTypeNames 2 | Should Be 'Mobile'
        Get-Name $MemoryTypeNames 99 | Should BeExactly '99'
        $null -eq (Get-Name $MemoryTypeNames $null) | Should Be $true
    }
    It 'drops SMBIOS placeholders' -TestCases @(
        @{ in = 'To Be Filled By O.E.M.' }
        @{ in = 'Default string' }
        @{ in = 'x.x' }
        @{ in = 'Unknown' }
        @{ in = '   ' }
        @{ in = '0' }
    ) {
        param($in)
        $null -eq (ConvertTo-CleanString $in) | Should Be $true
    }
    It 'trims real values' {
        ConvertTo-CleanString '  Example 8-Core Processor   ' | Should BeExactly 'Example 8-Core Processor'
        ConvertTo-CleanString 'Rev 1.0' | Should BeExactly 'Rev 1.0'
    }
    It 'reports firmware virtualization as enabled under a running hypervisor' {
        $r = Resolve-Virtualization -CimValue $false -HypervisorPresent $true
        $r.enabled | Should Be $true
        $r.source | Should Be 'hypervisor'
        $r = Resolve-Virtualization -CimValue $false -HypervisorPresent $false
        $r.enabled | Should Be $false
        $r.source | Should Be 'cim'
        $r = Resolve-Virtualization -CimValue $true -HypervisorPresent $null
        $r.enabled | Should Be $true
        $r.source | Should Be 'cim'
        $null -eq (Resolve-Virtualization -CimValue $null -HypervisorPresent $null).enabled | Should Be $true
    }
    It 'takes vendor and device IDs without the machine-specific instance part' {
        $ids = Get-PciIds 'PCI\VEN_10de&DEV_1a2b&SUBSYS_00000000&REV_A1\4&1111111&0&0008'
        $ids.vendorId | Should BeExactly '10DE'
        $ids.deviceId | Should BeExactly '1A2B'
        $null -eq (Get-PciIds 'ROOT\BasicDisplay\0000').vendorId | Should Be $true
    }
}

Describe 'Collector: hardware' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'hardware.json')
    $data = $env['data']
    $json = [IO.File]::ReadAllText((Join-Path $TestDrive 'hardware.json'), [Text.Encoding]::UTF8)

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'hardware') -join '; ' | Should Be ''
    }
    It 'is partial without admin rights only because of SMART counters' {
        if ($env['elevated']) {
            $env['status'] | Should Be 'ok'
        }
        else {
            $env['status'] | Should Be 'partial'
            ($env['errors'] | ForEach-Object { $_['source'] + '=' + $_['kind'] }) -join ',' | Should Be 'Get-StorageReliabilityCounter=AccessDenied'
        }
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'lists CPUs, memory modules and disks' {
        $data['cpus'].Count -ge 1 | Should Be $true
        $data['cpus'][0]['cores'] -ge 1 | Should Be $true
        $data['memory']['modules'].Count | Should Be @(Get-CimInstance Win32_PhysicalMemory).Count
        $data['disks'].Count | Should Be @(Get-PhysicalDisk).Count
    }
    It 'follows the hypervisor for the virtualization flag' {
        $data['system']['hypervisorPresent'] -is [bool] | Should Be $true
        foreach ($c in $data['cpus']) {
            if ($data['system']['hypervisorPresent']) {
                $c['virtualizationFirmwareEnabled'] | Should Be $true
                $c['virtualizationSource'] | Should Be 'hypervisor'
            }
            else { $c['virtualizationSource'] | Should Be 'cim' }
        }
    }
    It 'marks exactly one system disk' {
        @($data['disks'] | Where-Object { $_['isSystem'] -eq $true }).Count | Should Be 1
    }
    It 'reports GPU memory from the registry when the driver writes it' {
        foreach ($g in $data['gpus']) {
            if ($null -ne $g['memorySource']) { $g['memorySource'] | Should Match '^(registry|cim)$' }
        }
    }
    It 'reports SMART counters only with admin rights' {
        foreach ($d in $data['disks']) {
            if (-not $env['elevated']) { $null -eq $d['reliability'] | Should Be $true }
        }
    }
    It 'never writes serial numbers or the system UUID' {
        $data.Keys + @($data['disks'] | ForEach-Object { $_.Keys }) | Where-Object { $_ -match 'serial|uuid' } | Should BeNullOrEmpty
        $secrets = @(
            @(Get-CimInstance Win32_BIOS | ForEach-Object { $_.SerialNumber })
            @(Get-CimInstance Win32_BaseBoard | ForEach-Object { $_.SerialNumber })
            @(Get-PhysicalDisk | ForEach-Object { $_.SerialNumber })
            @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { $_.SerialNumber })
            (Get-CimInstance Win32_ComputerSystemProduct).UUID
        ) | Where-Object { $_ -and $_.Trim().Length -ge 4 -and $_.Trim() -notmatch '^(Default string|To Be Filled By O\.E\.M\.|0+|Unknown)$' } | ForEach-Object { $_.Trim() }
        foreach ($s in $secrets) { $json.Contains($s) | Should Be $false }
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 30000 | Should Be $true
    }
}
