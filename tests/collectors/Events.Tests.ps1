# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/events.ps1: the XPath builder and grouping on known
# input, and the collector against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\events.ps1'

Describe 'events helpers' {
    . $collector

    It 'builds an XPath with providers, IDs and the period' {
        New-EventXPath -Days 7 -Providers @('Tcpip', 'Netwtw14') -Ids @(10000, 10001) |
            Should BeExactly "*[System[Provider[@Name='Tcpip' or @Name='Netwtw14'] and (EventID=10000 or EventID=10001) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"
        New-EventXPath -Days 1 | Should BeExactly '*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]'
    }
    It 'drops provider names that could break the query' {
        $x = New-EventXPath -Days 1 -Providers @("bad' or 1=1 or @Name='x", 'Good-Name.1', 'Good-Name.1')
        $x | Should BeExactly "*[System[Provider[@Name='Good-Name.1'] and TimeCreated[timediff(@SystemTime) <= 86400000]]]"
    }
    It 'takes both the driver file name and the service name as providers' {
        $names = Get-DriverProviderNames -Adapters @(
            @{ driverFileName = 'rt68cx21x64.sys'; serviceName = $null }
            @{ driverFileName = $null; serviceName = 'rt68cx21' }
            @{ driverFileName = 'Netwtw14.sys'; serviceName = 'Netwtw14' }
            @{ driverFileName = ''; serviceName = '' }
        )
        , $names | Should BeOfType [object[]]
        ($names -join ',') | Should Be 'Netwtw14,rt68cx21,rt68cx21x64'
        (Get-DriverProviderNames -Adapters @()).Count | Should Be 0
    }
    It 'splits providers into chunks the event log accepts' {
        $chunks = Split-IntoChunks -Items @(1..32) -Size 15
        $chunks.Count | Should Be 3
        ($chunks | ForEach-Object { $_.Count }) -join ',' | Should Be '15,15,2'
        (Split-IntoChunks -Items @() -Size 15).Count | Should Be 0
        $xpath = New-EventXPath -Days 1 -Providers @(1..15 | ForEach-Object { "NoSuchProvider$_" })
        { Invoke-AllowNotFound { Get-WinEvent -LogName 'System' -FilterXPath $xpath -MaxEvents 1 -ErrorAction Stop } } | Should Not Throw
    }
    It 'accepts an XPath with a provider that does not exist on this machine' {
        $xpath = New-EventXPath -Days 1 -Providers @('NoSuchProviderForTunnelEye')
        { Invoke-AllowNotFound { Get-WinEvent -LogName 'System' -FilterXPath $xpath -ErrorAction Stop } } | Should Not Throw
    }

    $t0 = [datetime]::new(2026, 10, 20, 10, 0, 0, [DateTimeKind]::Utc)
    $events = @(
        [pscustomobject]@{ LogName = 'System'; ProviderName = 'Netwtw14'; Id = 7021; Level = 4; TimeCreated = $t0 }
        [pscustomobject]@{ LogName = 'System'; ProviderName = 'Netwtw14'; Id = 7021; Level = 4; TimeCreated = $t0.AddHours(2) }
        [pscustomobject]@{ LogName = 'System'; ProviderName = 'Netwtw14'; Id = 7021; Level = 4; TimeCreated = $t0.AddHours(1) }
        [pscustomobject]@{ LogName = 'System'; ProviderName = 'Tcpip'; Id = 4207; Level = 2; TimeCreated = $t0 }
        [pscustomobject]@{ LogName = 'Microsoft-Windows-NCSI/Operational'; ProviderName = 'Microsoft-Windows-NCSI'; Id = 4042; Level = 0; TimeCreated = $t0 }
    )

    It 'groups by log, provider, ID and level' {
        $g = Group-Events -Events $events -MaxTimes 200
        $g.Count | Should Be 3
        ($g | ForEach-Object { '{0}/{1}#{2}={3}' -f $_['logName'], $_['provider'], $_['eventId'], $_['count'] }) -join ',' |
            Should Be 'Microsoft-Windows-NCSI/Operational/Microsoft-Windows-NCSI#4042=1,System/Netwtw14#7021=3,System/Tcpip#4207=1'
    }
    It 'names levels; level 0 is Information' {
        $g = Group-Events -Events $events -MaxTimes 200
        $g[0]['level'] | Should Be 'Information'
        $g[2]['level'] | Should Be 'Error'
    }
    It 'keeps first and last time and the newest timestamps first' {
        $w = (Group-Events -Events $events -MaxTimes 200)[1]
        $w['firstTime'] | Should Be '2026-10-20T10:00:00.000Z'
        $w['lastTime'] | Should Be '2026-10-20T12:00:00.000Z'
        ($w['times'] -join ',') | Should Be '2026-10-20T12:00:00.000Z,2026-10-20T11:00:00.000Z,2026-10-20T10:00:00.000Z'
        $w['timesTruncated'] | Should Be $false
    }
    It 'caps the timestamps and says so' {
        $w = (Group-Events -Events $events -MaxTimes 2)[1]
        $w['count'] | Should Be 3
        $w['times'].Count | Should Be 2
        $w['timesTruncated'] | Should Be $true
    }
    It 'handles no events' {
        $g = Group-Events -Events @() -MaxTimes 200
        , $g | Should BeOfType [object[]]
        $g.Count | Should Be 0
    }
}

Describe 'Collector: events' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'events.json')
    $data = $env['data']
    $json = [IO.File]::ReadAllText((Join-Path $TestDrive 'events.json'), [Text.Encoding]::UTF8)

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'events') -join '; ' | Should Be ''
    }
    It 'is ok without admin rights' {
        $env['status'] | Should Be 'ok'
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'reports the logs it read' {
        foreach ($name in 'System', 'Application') {
            $log = $data['logs'] | Where-Object { $_['logName'] -eq $name }
            $log['exists'] | Should Be $true
            $log['readOk'] | Should Be $true
        }
        ($data['applicationProviders'] -join ',') | Should Be 'RasClient'
    }
    It 'includes the service names of physical adapter drivers' {
        $services = @(Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter = TRUE' | ForEach-Object { $_.ServiceName } | Where-Object { $_ })
        foreach ($s in $services) { $data['providers'] -contains $s | Should Be $true }
    }
    It 'keeps every event inside the period and counts consistent' {
        $since = [datetime]::Parse($data['since'], [Globalization.CultureInfo]::InvariantCulture, 'AdjustToUniversal')
        foreach ($g in $data['groups']) {
            $g['count'] -ge $g['times'].Count | Should Be $true
            foreach ($t in $g['times']) {
                [datetime]::Parse($t, [Globalization.CultureInfo]::InvariantCulture, 'AdjustToUniversal') -ge $since.AddMinutes(-5) | Should Be $true
            }
        }
    }
    It 'never stores messages or event data' {
        # Only the data section: the envelope's errors[] have a 'message' key.
        (ConvertTo-CollectorJson $data) | Should Not Match '"(message|properties|eventData|userId|machineName)"'
        $json | Should Not Match ([regex]::Escape($env:COMPUTERNAME))
        $json | Should Not Match ([regex]::Escape($env:USERNAME))
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 60000 | Should Be $true
    }
}
