# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'vpn': built-in Windows VPN profiles and services, third-party VPN
# clients, proxy tunnels and DPI bypass tools found by signatures
# (vpn-signatures.json): installed software, services, drivers, adapters and
# running processes. Kill switch and split tunneling of third-party clients
# are derived by the analyzer from 'routing' and 'firewall'.
# Schema: docs/schema/vpn.md. Read-only; no admin rights required.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

$SignaturesPath = Join-Path $PSScriptRoot 'vpn-signatures.json'
$BuiltInServiceNames = 'RasMan', 'RemoteAccess', 'IKEEXT', 'PolicyAgent', 'SstpSvc'
$UninstallKeys = @(
    @{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; scope = 'machine' }
    @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; scope = 'machine' }
    @{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; scope = 'user' }
)

function Test-Pattern {
    # Case-insensitive match of any value against a signature pattern (null = no pattern).
    param($Pattern, [object[]] $Values)
    if (-not $Pattern) { return $false }
    foreach ($v in $Values) {
        if ($null -ne $v -and [regex]::IsMatch([string]$v, $Pattern, 'IgnoreCase')) { return $true }
    }
    $false
}

function Get-SignatureValue {
    # Signatures come from JSON as Dictionary[string,object], whose indexer
    # throws on a missing key; optional fields read as $null.
    param($Signature, [string] $Key)
    if (([System.Collections.IDictionary]$Signature).Contains($Key)) { return $Signature[$Key] }
    $null
}

function Find-VpnClients {
    # Matches the inventory against signatures. Inventory: hashtable of arrays
    # services/drivers (name, displayName), adapters (name, interfaceDescription,
    # componentId), processes (name), software (displayName). Specific
    # signatures claim items first; generic ones get only unclaimed items.
    # Returns one entry per signature that matched anything, in signature order.
    param(
        [Parameter(Mandatory)][object[]] $Signatures,
        [Parameter(Mandatory)][hashtable] $Inventory
    )
    $sections = @(
        @{ key = 'services'; fields = @('name') }
        @{ key = 'drivers'; fields = @('name') }
        @{ key = 'adapters'; fields = @('name', 'interfaceDescription', 'componentId') }
        @{ key = 'processes'; fields = @('name') }
        @{ key = 'software'; fields = @('displayName') }
    )
    $claimed = @{}
    foreach ($s in $sections) { $claimed[$s.key] = @{} }

    $results = @{}
    $ordered = @(@($Signatures | Where-Object { -not (Get-SignatureValue $_ 'generic') }) + @($Signatures | Where-Object { Get-SignatureValue $_ 'generic' }))
    foreach ($sig in $ordered) {
        $match = [ordered]@{}
        $any = $false
        foreach ($s in $sections) {
            $items = [System.Collections.Generic.List[object]]::new()
            $pattern = Get-SignatureValue $sig $s.key
            $source = @($Inventory[$s.key])
            for ($i = 0; $i -lt $source.Count; $i++) {
                $item = $source[$i]
                if ($null -eq $item) { continue }
                if ((Get-SignatureValue $sig 'generic') -and $claimed[$s.key].ContainsKey($i)) { continue }
                $values = @(foreach ($f in $s.fields) { $item[$f] })
                if (Test-Pattern -Pattern $pattern -Values $values) {
                    $items.Add($item)
                    $claimed[$s.key][$i] = $true
                }
            }
            $match[$s.key] = $items.ToArray()
            if ($items.Count) { $any = $true }
        }
        if ($any) { $results[$sig['id']] = $match }
    }

    foreach ($sig in $Signatures) {
        if (-not $results.ContainsKey($sig['id'])) { continue }
        $m = $results[$sig['id']]
        [ordered]@{
            id        = $sig['id']
            name      = $sig['name']
            kind      = $sig['kind']
            generic   = [bool](Get-SignatureValue $sig 'generic')
            software  = $m['software']
            services  = $m['services']
            drivers   = $m['drivers']
            adapters  = $m['adapters']
            processes = $m['processes']
        }
    }
}

function Find-ProcessOwners {
    # Links processes of generic signatures (proxy cores such as xray) to a
    # specific client. Evidence, in order: an ancestor process (up to
    # $MaxDepth levels) belongs to the client ('parentProcess'), or the
    # executable lies in a folder of the client ('imagePath'). Instances:
    # @{ processId; parentProcessId; name (without .exe); path; startTicks }.
    # A parent started after its child is a reused PID, not the real parent.
    # ClientProcessNames / ClientDirectories: hashtables clientId -> string[].
    # Returns a hashtable: target process name -> array of @{ clientId; evidence }.
    # Paths are used for matching only and never returned.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Instances,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $TargetNames,
        [Parameter(Mandatory)][hashtable] $ClientProcessNames,
        [Parameter(Mandatory)][hashtable] $ClientDirectories,
        [int] $MaxDepth = 3
    )
    $byPid = @{}
    foreach ($i in $Instances) { $byPid[[int64]$i['processId']] = $i }
    $clientOfName = @{}
    foreach ($id in $ClientProcessNames.Keys) {
        foreach ($n in $ClientProcessNames[$id]) { $clientOfName[([string]$n).ToLowerInvariant()] = $id }
    }

    $result = @{}
    foreach ($target in $TargetNames) {
        $owners = [System.Collections.Generic.List[object]]::new()
        $seen = @{}
        foreach ($i in $Instances) {
            if ([string]$i['name'] -ne $target) { continue }
            $owner = $null
            $evidence = $null

            $current = $i
            $visited = @{ ([int64]$i['processId']) = $true }
            for ($depth = 0; $depth -lt $MaxDepth -and $null -eq $owner; $depth++) {
                $ppid = [int64]$current['parentProcessId']
                if ($visited.ContainsKey($ppid) -or -not $byPid.ContainsKey($ppid)) { break }
                $visited[$ppid] = $true
                $parent = $byPid[$ppid]
                if ($parent['startTicks'] -and $current['startTicks'] -and $parent['startTicks'] -gt $current['startTicks']) { break }
                $current = $parent
                $key = ([string]$current['name']).ToLowerInvariant()
                if ($clientOfName.ContainsKey($key)) { $owner = $clientOfName[$key]; $evidence = 'parentProcess' }
            }

            if ($null -eq $owner -and $i['path']) {
                foreach ($id in $ClientDirectories.Keys) {
                    foreach ($dir in $ClientDirectories[$id]) {
                        if (-not $dir) { continue }
                        $prefix = ([string]$dir).TrimEnd('\') + '\'
                        if (([string]$i['path']).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                            $owner = $id; $evidence = 'imagePath'; break
                        }
                    }
                    if ($null -ne $owner) { break }
                }
            }

            if ($null -ne $owner -and -not $seen.ContainsKey("$owner|$evidence")) {
                $seen["$owner|$evidence"] = $true
                $owners.Add([ordered]@{ clientId = $owner; evidence = $evidence })
            }
        }
        $result[$target] = $owners.ToArray()
    }
    $result
}

function ConvertTo-ServiceEntry {
    param($Service)
    $image = ConvertFrom-ServicePathName $Service.PathName
    $imagePath = $null
    $imageExists = $null
    $hasArguments = $false
    if ($null -ne $image) {
        $imagePath = Hide-UserProfilePath $image.path
        $hasArguments = $image.hasArguments
        try { $imageExists = Test-Path -LiteralPath ([Environment]::ExpandEnvironmentVariables($image.path)) -PathType Leaf } catch { }
    }
    [ordered]@{
        name         = $Service.Name
        displayName  = $Service.DisplayName
        state        = $Service.State
        startMode    = $Service.StartMode
        imagePath    = $imagePath
        imageExists  = $imageExists
        hasArguments = $hasArguments
    }
}

function ConvertTo-ProfileEntry {
    # One built-in VPN profile. EAP configuration XML and anything that could
    # hold secrets is not collected.
    param($Connection, [bool] $AllUser)
    $c = $Connection
    $routes = @(foreach ($r in @($c.Routes)) {
            if ($null -ne $r) { [ordered]@{ destinationPrefix = $r.DestinationPrefix; routeMetric = $r.RouteMetric } }
        })
    $servers = @(foreach ($s in @($c.ServerList)) {
            if ($null -ne $s) { [ordered]@{ serverAddress = $s.ServerAddress; friendlyName = $s.FriendlyName } }
        })
    $proxy = $null
    if ($null -ne $c.Proxy) {
        $server = Remove-UrlCredential $c.Proxy.ProxyServer
        $script = Remove-UrlCredential $c.Proxy.AutoConfigurationScript
        $proxy = [ordered]@{
            proxyServer         = $server.value
            autoConfigUrl       = $script.value
            bypassProxyForLocal = $c.Proxy.BypassProxyForLocal
            userInfoRemoved     = ($server.userInfoRemoved -or $script.userInfoRemoved)
        }
    }
    [ordered]@{
        name                  = $c.Name
        guid                  = if ($c.Guid) { ([string]$c.Guid).Trim('{}').ToLowerInvariant() } else { $null }
        allUserConnection     = $AllUser
        serverAddress         = $c.ServerAddress
        servers               = $servers
        tunnelType            = $c.TunnelType
        authenticationMethod  = @($c.AuthenticationMethod | ForEach-Object { [string]$_ })
        encryptionLevel       = $c.EncryptionLevel
        l2tpIPsecAuth         = $c.L2tpIPsecAuth
        connectionStatus      = $c.ConnectionStatus
        splitTunneling        = $c.SplitTunneling
        routes                = $routes
        dnsSuffix             = if ($c.DnsSuffix) { $c.DnsSuffix } else { $null }
        idleDisconnectSeconds = $c.IdleDisconnectSeconds
        rememberSignIn        = $c.RememberCredential
        useWindowsSignIn      = $c.UseWinlogonCredential
        proxy                 = $proxy
    }
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'vpn' -Version '1.1.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)

    # --- Built-in VPN ------------------------------------------------------

    $profiles = $null
    $userProfiles = Invoke-Source -Context $ctx -Source 'Get-VpnConnection' -AsList -ScriptBlock {
        Invoke-AllowNotFound { Get-VpnConnection -ErrorAction Stop }
    }
    $allUserProfiles = Invoke-Source -Context $ctx -Source 'Get-VpnConnection -AllUserConnection' -AsList -ScriptBlock {
        Invoke-AllowNotFound { Get-VpnConnection -AllUserConnection -ErrorAction Stop }
    }
    if ($null -ne $userProfiles -or $null -ne $allUserProfiles) {
        $profiles = @(
            foreach ($c in @($userProfiles)) { if ($null -ne $c) { ConvertTo-ProfileEntry -Connection $c -AllUser $false } }
            foreach ($c in @($allUserProfiles)) { if ($null -ne $c) { ConvertTo-ProfileEntry -Connection $c -AllUser $true } }
        )
    }

    # --- Inventory -----------------------------------------------------------

    $allServices = Invoke-Source -Context $ctx -Source 'Win32_Service' -AsList -ScriptBlock {
        Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
    }
    $allDrivers = Invoke-Source -Context $ctx -Source 'Win32_SystemDriver' -AsList -ScriptBlock {
        Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop
    }
    $adapters = Invoke-Source -Context $ctx -Source 'Get-NetAdapter' -AsList -ScriptBlock {
        Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object InterfaceIndex | ForEach-Object {
            [ordered]@{
                name                 = $_.Name
                interfaceDescription = $_.InterfaceDescription
                interfaceIndex       = [int]$_.InterfaceIndex
                componentId          = if ($_.ComponentID) { $_.ComponentID } else { $null }
                status               = $_.Status
            }
        }
    }
    # Names only: paths and command lines may reveal the user and secrets.
    $processes = Invoke-Source -Context $ctx -Source 'Get-Process' -AsList -ScriptBlock {
        Get-Process -ErrorAction Stop | Group-Object ProcessName | Sort-Object Name | ForEach-Object {
            [ordered]@{ name = $_.Name; count = $_.Count }
        }
    }
    # HKCU is the hive of the account the collector runs as (see dns-proxy).
    $software = Invoke-Source -Context $ctx -Source 'Uninstall' -AsList -ScriptBlock {
        $seen = @{}
        foreach ($k in $UninstallKeys) {
            if (-not (Test-Path -LiteralPath $k.path)) { continue }
            foreach ($item in (Get-ChildItem -LiteralPath $k.path -ErrorAction Stop)) {
                # Trimmed: some installers register the same name with trailing spaces.
                $name = ([string]$item.GetValue('DisplayName', '')).Trim()
                if (-not $name) { continue }
                $version = ([string]$item.GetValue('DisplayVersion', '')).Trim()
                $id = '{0}|{1}|{2}' -f $name, $version, $k.scope
                if ($seen.ContainsKey($id)) { continue }
                $seen[$id] = $true
                [ordered]@{
                    displayName    = $name
                    displayVersion = if ($version) { $version } else { $null }
                    publisher      = $item.GetValue('Publisher', $null)
                    scope          = $k.scope
                }
            }
        }
    }

    $builtInServices = $null
    if ($null -ne $allServices) {
        $builtInServices = @($allServices | Where-Object { $BuiltInServiceNames -contains $_.Name } | Sort-Object Name | ForEach-Object {
                [ordered]@{ name = $_.Name; state = $_.State; startMode = $_.StartMode }
            })
    }

    # --- Signature matching ------------------------------------------------

    $clients = $null
    $signatures = Invoke-Source -Context $ctx -Source 'vpn-signatures.json' -ScriptBlock {
        $doc = ConvertFrom-CollectorJson -Json ([IO.File]::ReadAllText($SignaturesPath, [Text.Encoding]::UTF8))
        , @($doc['clients'])
    }
    if ($null -ne $signatures) {
        # A failed inventory source is already in errors; matching runs on the rest.
        $inventory = @{
            services  = @(foreach ($s in @($allServices)) { if ($null -ne $s) { @{ name = $s.Name; displayName = $s.DisplayName; raw = $s } } })
            drivers   = @(foreach ($s in @($allDrivers)) { if ($null -ne $s) { @{ name = $s.Name; displayName = $s.DisplayName; raw = $s } } })
            adapters  = @($adapters | Where-Object { $null -ne $_ })
            processes = @($processes | Where-Object { $null -ne $_ })
            software  = @($software | Where-Object { $null -ne $_ })
        }
        $matched = @(Find-VpnClients -Signatures $signatures -Inventory $inventory)

        # Admin only: paths of other accounts' processes are hidden otherwise,
        # so without rights the owners of generic processes stay unknown (null).
        $owners = $null
        $targets = @($matched | Where-Object { $_['generic'] } | ForEach-Object { $_['processes'] } | ForEach-Object { $_['name'] })
        if ($ctx.Elevated -and $targets.Count) {
            $instances = Invoke-Source -Context $ctx -Source 'Win32_Process' -AsList -ScriptBlock {
                Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
                    @{
                        processId       = $_.ProcessId
                        parentProcessId = $_.ParentProcessId
                        name            = [IO.Path]::GetFileNameWithoutExtension([string]$_.Name)
                        path            = $_.ExecutablePath
                        startTicks      = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().Ticks } else { $null }
                    }
                }
            }
            if ($null -ne $instances) {
                $names = @{}
                $dirs = @{}
                $systemRoot = $env:SystemRoot.TrimEnd('\') + '\'
                foreach ($c in ($matched | Where-Object { -not $_['generic'] })) {
                    $names[$c['id']] = @($c['processes'] | ForEach-Object { $_['name'] })
                    $clientDirs = [System.Collections.Generic.List[string]]::new()
                    foreach ($s in $c['services']) {
                        $image = ConvertFrom-ServicePathName $s['raw'].PathName
                        if ($null -ne $image) { $clientDirs.Add((Split-Path -Parent ([Environment]::ExpandEnvironmentVariables($image.path)))) }
                    }
                    foreach ($i in $instances) {
                        if ($names[$c['id']] -contains $i['name'] -and $i['path']) { $clientDirs.Add((Split-Path -Parent $i['path'])) }
                    }
                    # Shared system folders would make every process there an owner match.
                    $dirs[$c['id']] = @($clientDirs | Where-Object { $_ -and -not ($_ + '\').StartsWith($systemRoot, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -Unique)
                }
                $owners = Find-ProcessOwners -Instances $instances -TargetNames $targets -ClientProcessNames $names -ClientDirectories $dirs
            }
        }

        $clients = @($matched | ForEach-Object {
                $_['services'] = @($_['services'] | ForEach-Object { ConvertTo-ServiceEntry $_['raw'] })
                $_['drivers'] = @($_['drivers'] | ForEach-Object { ConvertTo-ServiceEntry $_['raw'] })
                if ($_['generic']) {
                    $_['processes'] = @($_['processes'] | ForEach-Object {
                            $o = $null
                            if ($null -ne $owners -and $owners.ContainsKey($_['name'])) { $o = $owners[$_['name']] }
                            [ordered]@{ name = $_['name']; count = $_['count']; owners = $o }
                        })
                }
                $_
            })
    }

    [ordered]@{
        builtIn = [ordered]@{
            profiles = $profiles
            services = $builtInServices
        }
        clients = $clients
    }
}
