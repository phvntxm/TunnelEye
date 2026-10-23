# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'dns-proxy': DNS servers and suffixes per interface, global DNS
# settings, DoH, NRPT, DNS cache aggregates (D-003), user/machine/WinHTTP and
# environment proxy settings, hosts file.
# Schema: docs/schema/dns-proxy.md. Read-only; no admin rights required.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

$RecordTypeNames = @{ 1 = 'A'; 2 = 'NS'; 5 = 'CNAME'; 6 = 'SOA'; 12 = 'PTR'; 15 = 'MX'; 16 = 'TXT'; 28 = 'AAAA'; 33 = 'SRV'; 64 = 'SVCB'; 65 = 'HTTPS'; 255 = 'ANY' }
$CacheStatusNames = @{ 0 = 'Success'; 9002 = 'ServerFailure'; 9003 = 'NameError'; 9501 = 'NoRecords'; 9701 = 'RecordDoesNotExist' }
$MaxSuspiciousCacheEntries = 200

function Get-AddressFamilyName {
    # DnsClient cmdlets report the family as a number (AF_INET = 2, AF_INET6 = 23).
    param($Value)
    switch ([int]$Value) { 2 { 'IPv4' } 23 { 'IPv6' } default { [string]$Value } }
}

function Remove-UrlCredential {
    # Strips user:password@ from proxy strings and URLs: credentials must
    # never reach the snapshot. Returns @{ value; userInfoRemoved }.
    # Untyped on purpose: a [string] parameter would turn $null into ''.
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return @{ value = $null; userInfoRemoved = $false } }
    $Value = [string]$Value
    $clean = $Value -replace '(^|[=;\s]|://)[^@;=\s/]+@', '$1'
    @{ value = $clean; userInfoRemoved = ($clean -ne $Value) }
}

function ConvertFrom-ConnectionSettingsBlob {
    # Decodes DefaultConnectionSettings / WinHttpSettings: DWORD version,
    # DWORD counter, DWORD flags, then length-prefixed ANSI strings: proxy,
    # bypass list and (IE settings only) auto-config URL.
    # Flags: 1 direct, 2 proxy, 4 auto-config URL, 8 auto-detect.
    param([AllowNull()][byte[]] $Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -lt 12) { return $null }

    $flags = [BitConverter]::ToUInt32($Bytes, 8)
    $strings = New-Object System.Collections.Generic.List[string]
    $pos = 12
    while ($strings.Count -lt 3 -and $pos + 4 -le $Bytes.Length) {
        $len = [BitConverter]::ToInt32($Bytes, $pos)
        $pos += 4
        if ($len -lt 0 -or $pos + $len -gt $Bytes.Length) { break }
        $strings.Add([Text.Encoding]::Default.GetString($Bytes, $pos, $len))
        $pos += $len
    }
    $at = { param($i) if ($strings.Count -gt $i -and $strings[$i] -ne '') { $strings[$i] } else { $null } }
    [ordered]@{
        flags             = [int64]$flags
        proxyEnabled      = [bool]($flags -band 2)
        autoConfigEnabled = [bool]($flags -band 4)
        autoDetect        = [bool]($flags -band 8)
        proxyServer       = & $at 0
        bypassList        = & $at 1
        autoConfigUrl     = & $at 2
    }
}

function ConvertFrom-HostsFile {
    # Returns entries @{ address; names[] }; comments and blank lines skipped.
    param([AllowEmptyString()][string] $Text)
    foreach ($line in ($Text -split '\r?\n')) {
        $body = ($line -replace '#.*$', '').Trim()
        if (-not $body) { continue }
        $parts = @($body -split '\s+')
        if ($parts.Count -lt 2) { continue }
        [ordered]@{ address = $parts[0]; names = @($parts[1..($parts.Count - 1)]) }
    }
}

function Test-SinkholeAddress {
    param([AllowNull()][string] $Address)
    $Address -in '0.0.0.0', '::' -or $Address -match '^127\.' -or $Address -eq '::1'
}

function Get-InternetSettings {
    # Proxy values of an Internet Settings key; credentials stripped.
    param([string] $Path)
    $server = Remove-UrlCredential (Get-RegistryValue $Path 'ProxyServer')
    $pac = Remove-UrlCredential (Get-RegistryValue $Path 'AutoConfigURL')
    $enable = Get-RegistryValue $Path 'ProxyEnable'
    [ordered]@{
        proxyEnable    = if ($null -eq $enable) { $null } else { [int]$enable -eq 1 }
        proxyServer    = $server.value
        proxyOverride  = Get-RegistryValue $Path 'ProxyOverride'
        autoConfigUrl  = $pac.value
        userInfoRemoved = $server.userInfoRemoved -or $pac.userInfoRemoved
    }
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'dns-proxy' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)

    # --- DNS -------------------------------------------------------------

    $servers = Invoke-Source -Context $ctx -Source 'Get-DnsClientServerAddress' -AsList -ScriptBlock {
        Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object InterfaceIndex, AddressFamily | ForEach-Object {
            [ordered]@{
                interfaceIndex  = [int]$_.InterfaceIndex
                interfaceAlias  = $_.InterfaceAlias
                addressFamily   = Get-AddressFamilyName $_.AddressFamily
                serverAddresses = @($_.ServerAddresses)
            }
        }
    }

    $clients = Invoke-Source -Context $ctx -Source 'Get-DnsClient' -AsList -ScriptBlock {
        Get-DnsClient -ErrorAction Stop | Sort-Object InterfaceIndex | ForEach-Object {
            [ordered]@{
                interfaceIndex                     = [int]$_.InterfaceIndex
                interfaceAlias                     = $_.InterfaceAlias
                connectionSpecificSuffix           = if ($_.ConnectionSpecificSuffix) { $_.ConnectionSpecificSuffix } else { $null }
                connectionSpecificSuffixSearchList = @($_.ConnectionSpecificSuffixSearchList | Where-Object { $_ })
                registerThisConnectionsAddress     = [bool]$_.RegisterThisConnectionsAddress
                useSuffixWhenRegistering           = [bool]$_.UseSuffixWhenRegistering
            }
        }
    }

    $global = Invoke-Source -Context $ctx -Source 'Get-DnsClientGlobalSetting' -ScriptBlock {
        $g = Get-DnsClientGlobalSetting -ErrorAction Stop
        [ordered]@{
            suffixSearchList = @($g.SuffixSearchList | Where-Object { $_ })
            useDevolution    = [bool]$g.UseDevolution
            devolutionLevel  = $g.DevolutionLevel
        }
    }

    # Known DoH servers: the cmdlet exists on Windows 11 / Server 2022 only;
    # on Windows 10 the field is null without an error (no DoH support).
    $dohKnown = $null
    if (Get-Command -Name Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
        $dohKnown = Invoke-Source -Context $ctx -Source 'Get-DnsClientDohServerAddress' -AsList -ScriptBlock {
            Invoke-AllowNotFound { Get-DnsClientDohServerAddress -ErrorAction Stop } | Sort-Object ServerAddress | ForEach-Object {
                [ordered]@{
                    serverAddress      = $_.ServerAddress
                    dohTemplate        = $_.DohTemplate
                    allowFallbackToUdp = [bool]$_.AllowFallbackToUdp
                    autoUpgrade        = [bool]$_.AutoUpgrade
                }
            }
        }
    }

    # Per-interface DoH: InterfaceSpecificParameters\{guid}\Doh*Settings\Doh|Doh6\<server>.
    $dohInterfaces = Invoke-Source -Context $ctx -Source 'DoH interface settings' -AsList -ScriptBlock {
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters'
        if (Test-Path -LiteralPath $base) {
            foreach ($iface in (Get-ChildItem -LiteralPath $base -ErrorAction Stop)) {
                foreach ($kind in 'DohInterfaceSettings', 'DohProfileSettings') {
                    foreach ($family in 'Doh', 'Doh6') {
                        $path = Join-Path $iface.PSPath "$kind\$family"
                        if (-not (Test-Path -LiteralPath $path)) { continue }
                        foreach ($server in (Get-ChildItem -LiteralPath $path -ErrorAction Stop)) {
                            $flags = $server.GetValue('DohFlags', $null)
                            [ordered]@{
                                interfaceGuid = $iface.PSChildName.ToLowerInvariant()
                                settings      = if ($kind -eq 'DohInterfaceSettings') { 'Interface' } else { 'Profile' }
                                addressFamily = if ($family -eq 'Doh') { 'IPv4' } else { 'IPv6' }
                                serverAddress = $server.PSChildName
                                dohFlags      = if ($null -eq $flags) { $null } else { [int64]$flags }
                                dohTemplate   = $server.GetValue('DohTemplate', $null)
                            }
                        }
                    }
                }
            }
        }
    }

    $dohPolicy = Invoke-Source -Context $ctx -Source 'DoH policy' -ScriptBlock {
        [ordered]@{
            # Group Policy "Configure DNS over HTTPS": 0/1 prohibit, 2 allow, 3 require.
            dohPolicy     = Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DoHPolicy'
            enableAutoDoh = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableAutoDoh'
        }
    }

    $nrpt = Invoke-Source -Context $ctx -Source 'Get-DnsClientNrptPolicy' -AsList -ScriptBlock {
        Invoke-AllowNotFound { Get-DnsClientNrptPolicy -ErrorAction Stop } | ForEach-Object {
            $p = $_.PSObject.Properties
            $get = { param($n) if ($p[$n]) { $p[$n].Value } else { $null } }
            [ordered]@{
                namespace           = & $get 'Namespace'
                nameServers         = @(& $get 'NameServers' | Where-Object { $_ })
                queryPolicy         = & $get 'QueryPolicy'
                dnsSecEnabled       = & $get 'DnsSecEnabled'
                directAccessEnabled = & $get 'DirectAccessEnabled'
                nameEncoding        = & $get 'NameEncoding'
            }
        }
    }

    # --- hosts -------------------------------------------------------------

    $hosts = Invoke-Source -Context $ctx -Source 'hosts' -ScriptBlock {
        $dbPath = Get-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DataBasePath'
        if (-not $dbPath) { $dbPath = '%SystemRoot%\System32\drivers\etc' }
        $path = Join-Path ([Environment]::ExpandEnvironmentVariables($dbPath)) 'hosts'
        if (-not (Test-Path -LiteralPath $path)) {
            return [ordered]@{ path = $path; exists = $false; sizeBytes = $null; lastWriteTime = $null; entries = @() }
        }
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        $text = [IO.File]::ReadAllText($path, [Text.Encoding]::Default)
        [ordered]@{
            path          = $path
            exists        = $true
            sizeBytes     = $item.Length
            lastWriteTime = $item.LastWriteTimeUtc
            entries       = @(ConvertFrom-HostsFile $text)
        }
    }

    # --- DNS cache (D-003: aggregates and suspicious entries only) ----------

    $cache = Invoke-Source -Context $ctx -Source 'Get-DnsClientCache' -ScriptBlock {
        $records = @(Invoke-AllowNotFound { Get-DnsClientCache -ErrorAction Stop })
        $hostNames = @{}
        if ($null -ne $hosts) {
            foreach ($e in $hosts.entries) { foreach ($n in $e.names) { $hostNames[$n.TrimEnd('.')] = $true } }
        }

        # Windows preloads the whole hosts file into the cache, so names from
        # hosts are only counted (the hosts section already has them). Listed
        # are sinkhole answers (0.0.0.0, 127.x, ::) that did NOT come from
        # hosts: blocking or spoofing by the DNS server.
        $suspicious = New-Object System.Collections.Generic.List[object]
        $truncated = $false
        $fromHosts = 0
        foreach ($r in $records) {
            $name = ([string]$r.Entry).TrimEnd('.')
            if ($hostNames.ContainsKey($name)) { $fromHosts++; continue }
            $type = [int]$r.Type
            if ([int]$r.Status -ne 0 -or $type -notin 1, 28 -or -not (Test-SinkholeAddress $r.Data)) { continue }
            if ($suspicious.Count -ge $MaxSuspiciousCacheEntries) { $truncated = $true; continue }
            $suspicious.Add([ordered]@{
                    name = $name
                    type = $RecordTypeNames[$type]
                    data = [string]$r.Data
                })
        }

        [ordered]@{
            total               = $records.Count
            fromHosts           = $fromHosts
            byStatus            = @($records | Group-Object { [int]$_.Status } | Sort-Object { [int]$_.Name } | ForEach-Object {
                    $code = [int]$_.Name
                    [ordered]@{ status = $code; statusName = $CacheStatusNames[$code]; count = $_.Count }
                })
            byType              = @($records | Group-Object { [int]$_.Type } | Sort-Object { [int]$_.Name } | ForEach-Object {
                    $code = [int]$_.Name
                    [ordered]@{ type = $code; typeName = $RecordTypeNames[$code]; count = $_.Count }
                })
            suspicious          = $suspicious.ToArray()
            suspiciousTruncated = $truncated
        }
    }

    # --- Proxy -------------------------------------------------------------

    # HKCU is the hive of the account the collector runs as: with UAC
    # elevation by a different admin account it is not the interactive user's.
    $userProxy = Invoke-Source -Context $ctx -Source 'HKCU Internet Settings' -ScriptBlock {
        $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $settings = Get-InternetSettings $path
        $blob = ConvertFrom-ConnectionSettingsBlob (Get-RegistryValue "$path\Connections" 'DefaultConnectionSettings')
        if ($null -ne $blob) {
            $blob.proxyServer = (Remove-UrlCredential $blob.proxyServer).value
            $blob.autoConfigUrl = (Remove-UrlCredential $blob.autoConfigUrl).value
        }
        $settings['connectionSettings'] = $blob
        $settings
    }

    $machineProxy = Invoke-Source -Context $ctx -Source 'HKLM Internet Settings' -ScriptBlock {
        $settings = Get-InternetSettings 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
        # Policy ProxySettingsPerUser = 0 makes the HKLM settings apply to all users.
        $settings['proxySettingsPerUser'] = Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxySettingsPerUser'
        $settings
    }

    $winhttp = Invoke-Source -Context $ctx -Source 'WinHttpSettings' -ScriptBlock {
        $blob = ConvertFrom-ConnectionSettingsBlob (Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' 'WinHttpSettings')
        if ($null -eq $blob) {
            return [ordered]@{ direct = $true; proxyServer = $null; bypassList = $null }
        }
        $server = Remove-UrlCredential $blob.proxyServer
        [ordered]@{
            direct      = -not $blob.proxyEnabled
            proxyServer = $server.value
            bypassList  = $blob.bypassList
        }
    }
    $netshProxy = Invoke-NativeCommand -Context $ctx -Source 'netsh winhttp show proxy' `
        -FilePath (Join-Path $env:SystemRoot 'System32\netsh.exe') -ArgumentList 'winhttp', 'show', 'proxy'
    if ($null -ne $winhttp) {
        $winhttp['raw'] = if ($null -ne $netshProxy) { (Remove-UrlCredential $netshProxy.stdout.Trim()).value } else { $null }
    }

    $envProxy = Invoke-Source -Context $ctx -Source 'environment' -AsList -ScriptBlock {
        foreach ($scope in 'Machine', 'User') {
            foreach ($name in 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY') {
                $value = [Environment]::GetEnvironmentVariable($name, $scope)
                if (-not $value) { continue }
                $clean = Remove-UrlCredential $value
                [ordered]@{ scope = $scope; name = $name; value = $clean.value; userInfoRemoved = $clean.userInfoRemoved }
            }
        }
    }

    [ordered]@{
        dnsServers = $servers
        dnsClients = $clients
        dnsGlobal  = $global
        doh        = [ordered]@{
            knownServers = $dohKnown
            interfaces   = $dohInterfaces
            policy       = $dohPolicy
        }
        nrpt       = $nrpt
        dnsCache   = $cache
        hosts      = $hosts
        proxy      = [ordered]@{
            user        = $userProxy
            machine     = $machineProxy
            winhttp     = $winhttp
            environment = $envProxy
        }
    }
}
