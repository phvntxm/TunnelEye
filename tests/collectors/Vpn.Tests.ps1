# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/vpn.ps1: path parsing and signature matching on known
# input, the signature file, and the collector against the live machine.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
$collector = Join-Path (Get-RepoRoot) 'collectors\vpn.ps1'
$signaturesFile = Join-Path (Get-RepoRoot) 'collectors\vpn-signatures.json'

Describe 'vpn helpers' {
    . $collector

    It 'splits service image paths and drops arguments' -TestCases @(
        @{ in = '"C:\Program Files\Happ\happd.exe"'; path = 'C:\Program Files\Happ\happd.exe'; hasArgs = $false }
        @{ in = '"C:\Tools\winws2.exe" --wf-tcp-out=443 --token=x'; path = 'C:\Tools\winws2.exe'; hasArgs = $true }
        @{ in = 'C:\Windows\system32\svchost.exe -k netsvcs -p'; path = 'C:\Windows\system32\svchost.exe'; hasArgs = $true }
        @{ in = 'C:\Program Files\No Quotes\agent.exe /service'; path = 'C:\Program Files\No Quotes\agent.exe'; hasArgs = $true }
        @{ in = '\SystemRoot\System32\drivers\tap0901.sys'; path = '%SystemRoot%\System32\drivers\tap0901.sys'; hasArgs = $false }
        @{ in = 'System32\drivers\wintun.sys'; path = '%SystemRoot%\System32\drivers\wintun.sys'; hasArgs = $false }
        @{ in = '\??\C:\Tools\WinDivert64.sys'; path = 'C:\Tools\WinDivert64.sys'; hasArgs = $false }
    ) {
        param($in, $path, $hasArgs)
        $r = ConvertFrom-ServicePathName $in
        $r.path | Should BeExactly $path
        $r.hasArguments | Should Be $hasArgs
    }
    It 'returns null for empty image paths' {
        $null -eq (ConvertFrom-ServicePathName $null) | Should Be $true
        $null -eq (ConvertFrom-ServicePathName '  ') | Should Be $true
    }
    It 'hides the user profile folder in paths' {
        Hide-UserProfilePath 'C:\Users\someone\Documents\zapret2\winws2.exe' | Should BeExactly '%USERPROFILE%\Documents\zapret2\winws2.exe'
        Hide-UserProfilePath 'C:\Program Files\Happ\happd.exe' | Should BeExactly 'C:\Program Files\Happ\happd.exe'
        $null -eq (Hide-UserProfilePath $null) | Should Be $true
    }

    $signatures = @(
        @{ id = 'client-a'; name = 'Client A'; kind = 'vpn'; services = '^AgentA$'; drivers = $null; adapters = 'Alpha Adapter'; processes = '^agenta$'; software = '^Client A' }
        @{ id = 'client-b'; name = 'Client B'; kind = 'proxy-tunnel'; services = $null; drivers = $null; adapters = '^b-tun$'; processes = '^clientb$'; software = $null }
        @{ id = 'wintun'; name = 'Wintun'; kind = 'driver'; generic = $true; services = $null; drivers = '^wintun$'; adapters = '^Wintun'; processes = $null; software = $null }
        @{ id = 'unused'; name = 'Unused'; kind = 'vpn'; services = '^Nothing$'; drivers = $null; adapters = $null; processes = $null; software = $null }
    )
    $inventory = @{
        services  = @(@{ name = 'agenta'; displayName = 'Agent A' }, @{ name = 'Dhcp'; displayName = 'DHCP Client' })
        drivers   = @(@{ name = 'wintun'; displayName = 'wintun' })
        adapters  = @(
            @{ name = 'Ethernet 7'; interfaceDescription = 'Alpha Adapter V2'; componentId = 'alpha'; interfaceIndex = 7; status = 'Up' }
            @{ name = 'b-tun'; interfaceDescription = 'Wintun Userspace Tunnel'; componentId = 'wintun'; interfaceIndex = 9; status = 'Up' }
            @{ name = 'Wi-Fi'; interfaceDescription = 'Intel Wi-Fi 6E'; componentId = 'pci'; interfaceIndex = 3; status = 'Up' }
            @{ name = 'wintun0'; interfaceDescription = 'Wintun Userspace Tunnel'; componentId = 'wintun'; interfaceIndex = 11; status = 'Up' }
        )
        processes = @(@{ name = 'AgentA'; count = 1 }, @{ name = 'explorer'; count = 1 })
        software  = @(@{ displayName = 'Client A 2.0'; displayVersion = '2.0'; scope = 'machine' })
    }
    $result = @(Find-VpnClients -Signatures $signatures -Inventory $inventory)

    It 'reports only signatures that matched something, in signature order' {
        ($result | ForEach-Object { $_['id'] }) -join ',' | Should Be 'client-a,client-b,wintun'
    }
    It 'matches case-insensitively in every section' {
        $a = $result[0]
        $a['services'].Count | Should Be 1
        $a['processes'][0]['name'] | Should Be 'AgentA'
        $a['software'][0]['displayName'] | Should Be 'Client A 2.0'
        $a['adapters'][0]['interfaceIndex'] | Should Be 7
    }
    It 'gives a generic signature only items no specific one claimed' {
        $w = $result[2]
        $w['generic'] | Should Be $true
        ($w['adapters'] | ForEach-Object { $_['interfaceIndex'] }) -join ',' | Should Be '11'
        $w['drivers'].Count | Should Be 1
        ($result[1]['adapters'] | ForEach-Object { $_['interfaceIndex'] }) -join ',' | Should Be '9'
    }
    It 'keeps every section an array, even empty' {
        foreach ($c in $result) {
            foreach ($key in 'software', 'services', 'drivers', 'adapters', 'processes') {
                , $c[$key] | Should BeOfType [object[]]
            }
        }
    }
    It 'reads optional signature fields from JSON dictionaries' {
        $doc = ConvertFrom-CollectorJson -Json '{"clients":[{"id":"x","name":"X","kind":"vpn","processes":"^x$"}]}'
        $r = @(Find-VpnClients -Signatures @($doc['clients']) -Inventory @{ processes = @(@{ name = 'X'; count = 2 }) })
        $r.Count | Should Be 1
        $r[0]['generic'] | Should Be $false
    }
}

Describe 'vpn process owners' {
    . $collector

    $t0 = [datetime]::new(2026, 10, 23, 8, 0, 0).Ticks
    $instances = @(
        @{ processId = 4; parentProcessId = 0; name = 'System'; path = $null; startTicks = $t0 }
        @{ processId = 100; parentProcessId = 4; name = 'Happ'; path = 'C:\Program Files\Vendor\Happ\Happ.exe'; startTicks = $t0 + 10 }
        @{ processId = 200; parentProcessId = 100; name = 'xray'; path = 'C:\Program Files\Vendor\Happ\core\xray.exe'; startTicks = $t0 + 20 }
        @{ processId = 300; parentProcessId = 4; name = 'sing-box'; path = 'C:\Program Files\Vendor\Happ\core\sing-box.exe'; startTicks = $t0 + 30 }
        @{ processId = 400; parentProcessId = 4; name = 'mihomo'; path = 'C:\Tools\mihomo.exe'; startTicks = $t0 + 40 }
        @{ processId = 500; parentProcessId = 410; name = 'helper'; path = $null; startTicks = $t0 + 50 }
        @{ processId = 510; parentProcessId = 500; name = 'v2ray'; path = 'D:\v2ray\v2ray.exe'; startTicks = $t0 + 60 }
        @{ processId = 410; parentProcessId = 4; name = 'Happ'; path = $null; startTicks = $t0 + 70 }
    )
    $names = @{ happ = @('Happ', 'happd') }
    $dirs = @{ happ = @('C:\Program Files\Vendor\Happ') }
    $owners = Find-ProcessOwners -Instances $instances -TargetNames @('xray', 'sing-box', 'mihomo', 'v2ray', 'absent') `
        -ClientProcessNames $names -ClientDirectories $dirs

    It 'links a core to the client by its parent process' {
        $owners['xray'].Count | Should Be 1
        $owners['xray'][0]['clientId'] | Should Be 'happ'
        $owners['xray'][0]['evidence'] | Should Be 'parentProcess'
    }
    It 'links a core to the client by the folder of its executable' {
        $owners['sing-box'][0]['clientId'] | Should Be 'happ'
        $owners['sing-box'][0]['evidence'] | Should Be 'imagePath'
    }
    It 'leaves unrelated cores without owners' {
        $owners['mihomo'].Count | Should Be 0
        $owners['absent'].Count | Should Be 0
    }
    It 'does not trust a parent PID reused by a later process' {
        # v2ray -> helper (pid 500) -> pid 410, but 410 started after both.
        $owners['v2ray'].Count | Should Be 0
    }
    It 'never returns paths' {
        (ConvertTo-CollectorJson $owners) | Should Not Match 'Program Files|\\\\'
    }
}
Describe 'vpn signatures file' {
    $doc = ConvertFrom-CollectorJson -Json ([IO.File]::ReadAllText($signaturesFile, [Text.Encoding]::UTF8))
    $clients = @($doc['clients'])

    It 'has the expected schema and entries' {
        $doc['schema'] | Should Be 'tunneleye.vpn-signatures/1'
        $clients.Count -gt 0 | Should Be $true
    }
    It 'has unique ids, known kinds and valid patterns' {
        $ids = @{}
        $bad = foreach ($c in $clients) {
            if ($c['id'] -notmatch '^[a-z][a-z0-9-]*$' -or $ids.ContainsKey($c['id'])) { "id $($c['id'])" }
            $ids[$c['id']] = $true
            if ('vpn', 'mesh', 'proxy-tunnel', 'dpi-bypass', 'driver' -notcontains $c['kind']) { "kind $($c['id'])" }
            if (-not $c['name']) { "name $($c['id'])" }
            foreach ($key in 'services', 'drivers', 'adapters', 'processes', 'software') {
                if (-not $c.ContainsKey($key)) { "missing $key in $($c['id'])"; continue }
                if ($null -ne $c[$key]) {
                    try { [void][regex]::new($c[$key]) } catch { "regex $key in $($c['id'])" }
                }
            }
        }
        @($bad) -join '; ' | Should Be ''
    }
    It 'is ASCII-only' {
        @([IO.File]::ReadAllBytes($signaturesFile) | Where-Object { $_ -gt 127 }).Count | Should Be 0
    }
}

Describe 'Collector: vpn' {
    $env = Invoke-CollectorScript -Path $collector -OutFile (Join-Path $TestDrive 'vpn.json')
    $data = $env['data']
    $json = [IO.File]::ReadAllText((Join-Path $TestDrive 'vpn.json'), [Text.Encoding]::UTF8)

    It 'produces a valid envelope' {
        (Get-EnvelopeProblems -Envelope $env -Module 'vpn') -join '; ' | Should Be ''
    }
    It 'is ok without admin rights' {
        $env['status'] | Should Be 'ok'
    }
    It 'uses camelCase keys and no secret-like keys' {
        (Get-NonCamelCaseKeys -Node $data) -join '; ' | Should Be ''
        (Get-SensitiveKeys -Node $data) -join '; ' | Should Be ''
    }
    It 'lists the built-in VPN profiles of the user' {
        $expected = @(Get-VpnConnection -ErrorAction SilentlyContinue).Count + @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue).Count
        $data['builtIn']['profiles'].Count | Should Be $expected
        foreach ($p in $data['builtIn']['profiles']) {
            $p['splitTunneling'] -is [bool] | Should Be $true
            , $p['routes'] | Should BeOfType [object[]]
            , $p['authenticationMethod'] | Should BeOfType [object[]]
        }
    }
    It 'reports the built-in VPN services' {
        ($data['builtIn']['services'] | ForEach-Object { $_['name'] }) -contains 'RasMan' | Should Be $true
    }
    It 'reports clients with array sections' {
        , $data['clients'] | Should BeOfType [object[]]
        foreach ($c in $data['clients']) {
            foreach ($key in 'software', 'services', 'drivers', 'adapters', 'processes') {
                , $c[$key] | Should BeOfType [object[]]
            }
        }
    }
    It 'finds every running service that a signature names' {
        $doc = ConvertFrom-CollectorJson -Json ([IO.File]::ReadAllText($signaturesFile, [Text.Encoding]::UTF8))
        $patterns = @($doc['clients'] | ForEach-Object { if ($_.ContainsKey('services') -and $_['services']) { $_['services'] } })
        $expected = @(Get-CimInstance Win32_Service | Where-Object {
                $n = $_.Name; @($patterns | Where-Object { [regex]::IsMatch($n, $_, 'IgnoreCase') }).Count
            } | ForEach-Object { $_.Name } | Sort-Object)
        $found = @($data['clients'] | ForEach-Object { $_['services'] } | ForEach-Object { $_['name'] } | Sort-Object)
        $found -join ',' | Should Be ($expected -join ',')
    }
    It 'reports owners of generic processes only with admin rights' {
        foreach ($c in @($data['clients'] | Where-Object { $_['generic'] })) {
            foreach ($p in $c['processes']) {
                if ($env['elevated']) { , $p['owners'] | Should BeOfType [object[]] }
                else { $null -eq $p['owners'] | Should Be $true }
            }
        }
    }
    It 'never writes the user profile folder, command lines or process paths' {
        $profileDir = [regex]::Escape(($env:USERPROFILE -replace '\\', '\\'))
        $json | Should Not Match $profileDir
        $json | Should Not Match '"(commandLine|path|executablePath)"'
    }
    It 'finishes well within the per-module budget' {
        $env['durationMs'] -lt 30000 | Should Be $true
    }
}
