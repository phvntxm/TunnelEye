# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/routing.ps1 against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\routing.ps1'

Describe 'Routing helpers' {
    . $collector

    It 'effective metric is route + interface metric, null if either is unknown' {
        (Get-EffectiveMetric 256 35)[1] | Should Be 291
        $null -eq (Get-EffectiveMetric 0 $null)[1] | Should Be $true
        $null -eq (Get-EffectiveMetric $null 35)[1] | Should Be $true
    }
    It 'treats "network unreachable" (Win32 1231) as reachable = false' {
        # Same FullyQualifiedErrorId as the real cmdlet returns with no IPv6 route.
        Mock Find-NetRoute {
            throw (New-Object System.Management.Automation.ErrorRecord ([Exception]'The network location cannot be reached.'),
                'Windows System Error 1231,Find-NetRoute', 'NotSpecified', $null)
        }
        $r = Find-RouteSelection -Kind 'externalIPv6' -Target '2001:db8::1' -MetricMap @{}
        $r.reachable | Should Be $false
        $null -eq $r.interfaceIndex | Should Be $true
    }
    It 'rethrows other lookup errors' {
        Mock Find-NetRoute { throw [UnauthorizedAccessException]'denied' }
        { Find-RouteSelection -Kind 'gateway' -Target '10.0.0.1' -MetricMap @{} } | Should Throw 'denied'
    }
}

Describe 'Collector: routing' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'routing.json')
    $data = $env['data']
    $elevated = $env['elevated']

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'routing') -join '; ' | Should Be ''
    }
    It 'is ok with admin; without admin partial only because of the ICS list' {
        if ($elevated) {
            $env['status'] | Should Be 'ok'
        }
        else {
            $env['status'] | Should Be 'partial'
            (@($env['errors'] | ForEach-Object { "$($_['source'])=$($_['kind'])" }) -join ',') | Should Be 'HNetCfg.HNetShare=AccessDenied'
            $null -eq $data['ics']['connections'] | Should Be $true
        }
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'has every route of the live table, both families' {
        $live = @(Get-NetRoute)
        $data['routes'].Count | Should Be $live.Count
        $families = @($data['routes'] | ForEach-Object { $_['addressFamily'] } | Sort-Object -Unique)
        foreach ($f in $families) { $f | Should Match '^IPv(4|6)$' }
    }
    It 'reports the same default routes as the system' {
        $live = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction SilentlyContinue |
                ForEach-Object { "$($_.InterfaceIndex)|$($_.NextHop)" } | Sort-Object)
        $got = @($data['routes'] | Where-Object { $_['destinationPrefix'] -in '0.0.0.0/0', '::/0' } |
                ForEach-Object { "$($_['interfaceIndex'])|$($_['nextHop'])" } | Sort-Object)
        ($got -join ',') | Should Be ($live -join ',')
    }
    It 'route records have typed fields' {
        foreach ($r in $data['routes']) {
            $r['interfaceIndex'] -is [int] | Should Be $true
            $r['protocol'] | Should Match '^[A-Za-z]+$'
        }
    }
    It 'stores the effective metric of every route' {
        foreach ($r in $data['routes']) {
            if ($null -ne $r['interfaceMetric']) {
                $r['effectiveMetric'] | Should Be ($r['routeMetric'] + $r['interfaceMetric'])
            }
            else {
                $null -eq $r['effectiveMetric'] | Should Be $true
            }
        }
    }
    It 'selects routes for external IPv4, external IPv6 and every default gateway' {
        $kinds = @($data['routeSelection'] | ForEach-Object { "$($_['kind'])=$($_['target'])" })
        $kinds -contains 'externalIPv4=192.0.2.1' | Should Be $true
        $kinds -contains 'externalIPv6=2001:db8::1' | Should Be $true
        $gateways = @($data['routes'] | Where-Object { $_['destinationPrefix'] -in '0.0.0.0/0', '::/0' -and $_['nextHop'] -notin '0.0.0.0', '::' } |
                ForEach-Object { $_['nextHop'] } | Sort-Object -Unique)
        foreach ($g in $gateways) { $kinds -contains "gateway=$g" | Should Be $true }
    }
    It 'route selection matches Find-NetRoute on the live machine' {
        foreach ($s in $data['routeSelection']) {
            $s['reachable'] -is [bool] | Should Be $true
            $live = @(Find-NetRoute -RemoteIPAddress $s['target'] -ErrorAction SilentlyContinue |
                    Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' })
            if ($s['reachable']) {
                $s['interfaceIndex'] | Should Be ([int]$live[0].InterfaceIndex)
                $s['destinationPrefix'] | Should Be $live[0].DestinationPrefix
                $s['sourceAddress'] | Should Not BeNullOrEmpty
            }
            else {
                $live.Count | Should Be 0
            }
        }
    }
    It 'lists persistent routes as an array (empty store is not an error)' {
        , $data['persistentRoutes'] | Should BeOfType [object[]]
    }
    It 'IP interfaces have boolean flags and metrics' {
        $data['interfaces'].Count | Should Be @(Get-NetIPInterface).Count
        foreach ($i in $data['interfaces']) {
            foreach ($key in 'automaticMetric', 'forwarding', 'dhcp', 'weakHostSend', 'weakHostReceive') {
                ($null -eq $i[$key] -or $i[$key] -is [bool]) | Should Be $true
            }
            $i['connectionState'] | Should Match '^[A-Za-z]+$'
        }
    }
    It 'lists IP addresses with prefix length' {
        $data['addresses'].Count | Should Be @(Get-NetIPAddress).Count
        foreach ($a in $data['addresses']) { $a['prefixLength'] -is [int] | Should Be $true }
    }
    It 'reports bridge adapters and members as arrays' {
        , $data['bridge']['adapters'] | Should BeOfType [object[]]
        , $data['bridge']['members'] | Should BeOfType [object[]]
    }
    It 'reports the ICS service' {
        $data['ics']['service']['status'] | Should Match '^[A-Za-z]+$'
        $data.ContainsKey('ipEnableRouter') | Should Be $true
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 30000 | Should Be $true
    }
}
