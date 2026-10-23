# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Collector 'services': Windows services and kernel drivers with their image
# file and its vendor, autostart entries (Run keys, Startup folders),
# scheduled tasks (third-party in full, Microsoft as counts) and NDIS
# lightweight filters (LWF).
# Schema: docs/schema/services.md. Read-only; no admin rights required.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot 'TunnelEye.Common.psm1') -Force

$NetServiceClassKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}'
$RunKeys = @(
    @{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; location = 'HKLM\Run'; approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
    @{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; location = 'HKLM\RunOnce'; approved = $null }
    @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; location = 'HKLM\Run (32-bit)'; approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' }
    @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; location = 'HKLM\RunOnce (32-bit)'; approved = $null }
    @{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; location = 'HKCU\Run'; approved = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
    @{ path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; location = 'HKCU\RunOnce'; approved = $null }
)
$FilterTypeNames = @{ 1 = 'monitoring'; 2 = 'modifying' }
$FilterRunTypeNames = @{ 1 = 'mandatory'; 2 = 'optional' }

function Get-AccountClass {
    # Maps a service or task account to a class; user and machine names
    # never reach the snapshot. Returns $null for an empty account.
    param($Account)
    if ($null -eq $Account -or ([string]$Account).Trim() -eq '') { return $null }
    $a = ([string]$Account).Trim()
    switch -Regex ($a) {
        '^(LocalSystem|SYSTEM|NT AUTHORITY\\SYSTEM|S-1-5-18)$' { return 'localSystem' }
        '^(LOCAL SERVICE|NT AUTHORITY\\LocalService|NT AUTHORITY\\LOCAL SERVICE|S-1-5-19)$' { return 'localService' }
        '^(NETWORK SERVICE|NT AUTHORITY\\NetworkService|NT AUTHORITY\\NETWORK SERVICE|S-1-5-20)$' { return 'networkService' }
        '^NT SERVICE\\' { return 'virtualService' }
        '^(INTERACTIVE|NT AUTHORITY\\INTERACTIVE|S-1-5-4)$' { return 'interactive' }
        '^(Users|BUILTIN\\Users|S-1-5-32-545)$' { return 'users' }
        '^(Administrators|BUILTIN\\Administrators|S-1-5-32-544)$' { return 'administrators' }
        '^(Authenticated Users|NT AUTHORITY\\Authenticated Users|S-1-5-11)$' { return 'authenticatedUsers' }
    }
    'userAccount'
}

function Get-StartupApprovedState {
    # Task Manager "Startup" state: StartupApproved\<name> binary, first byte
    # even (02, 06) = enabled, odd (03, 07) = disabled. No value = enabled.
    param($Bytes)
    if ($null -eq $Bytes -or @($Bytes).Count -eq 0) { return $true }
    (([byte[]]$Bytes)[0] -band 1) -eq 0
}

function Get-ImageInfo {
    # @{ imagePath; imageExists; hasArguments; company } for a command line or
    # ImagePath; the profile folder is hidden, arguments are dropped. Vendor
    # lookups are cached: hundreds of services share few files (svchost).
    param($CommandLine, [hashtable] $Cache)
    $image = ConvertFrom-ServicePathName $CommandLine
    if ($null -eq $image) { return @{ imagePath = $null; imageExists = $null; hasArguments = $false; company = $null } }
    $full = [Environment]::ExpandEnvironmentVariables($image.path)
    if (-not $Cache.ContainsKey($full)) {
        $exists = $null
        $company = $null
        try {
            $exists = Test-Path -LiteralPath $full -PathType Leaf
            if ($exists) {
                $company = [Diagnostics.FileVersionInfo]::GetVersionInfo($full).CompanyName
                if ($company) { $company = $company.Trim() } else { $company = $null }
            }
        }
        catch { }
        $Cache[$full] = @{ exists = $exists; company = $company }
    }
    @{
        imagePath    = Hide-UserProfilePath $image.path
        imageExists  = $Cache[$full].exists
        hasArguments = $image.hasArguments
        company      = $Cache[$full].company
    }
}

function ConvertTo-TaskEntry {
    # One scheduled task. Author, descriptions and action arguments are not
    # collected; accounts become classes, SIDs and profile folders are hidden.
    param($Task, [hashtable] $Cache)
    $principal = $null
    if ($null -ne $Task.Principal) {
        $account = if ($Task.Principal.UserId) { $Task.Principal.UserId } else { $Task.Principal.GroupId }
        $principal = [ordered]@{
            account  = Get-AccountClass $account
            runLevel = [string]$Task.Principal.RunLevel
        }
    }
    $actions = @(foreach ($a in @($Task.Actions)) {
            if ($null -eq $a) { continue }
            if ($a.PSObject.Properties['Execute'] -and $a.Execute) {
                $quoted = [string]$a.Execute
                if ($quoted -notmatch '^"' -and $quoted -match '\s') { $quoted = '"' + $quoted + '"' }
                $info = Get-ImageInfo -CommandLine $quoted -Cache $Cache
                [ordered]@{
                    type         = 'exec'
                    imagePath    = $info.imagePath
                    imageExists  = $info.imageExists
                    hasArguments = [bool]($a.Arguments)
                    company      = $info.company
                    classId      = $null
                }
            }
            elseif ($a.PSObject.Properties['ClassId'] -and $a.ClassId) {
                [ordered]@{ type = 'comHandler'; imagePath = $null; imageExists = $null; hasArguments = $false; company = $null; classId = [string]$a.ClassId }
            }
        })
    $triggers = @(foreach ($t in @($Task.Triggers)) {
            if ($null -eq $t) { continue }
            # CIM class names: MSFT_TaskLogonTrigger -> logon.
            $kind = ($t.CimClass.CimClassName -replace '^MSFT_Task', '' -replace 'Trigger$', '')
            if ($kind -eq '') { $kind = 'time' }
            [ordered]@{ kind = $kind.Substring(0, 1).ToLowerInvariant() + $kind.Substring(1); enabled = [bool]$t.Enabled }
        })
    [ordered]@{
        taskPath  = Hide-UserProfilePath $Task.TaskPath
        taskName  = Hide-UserProfilePath $Task.TaskName
        state     = [string]$Task.State
        principal = $principal
        triggers  = $triggers
        actions   = $actions
    }
}

# Dot-sourcing (tests) loads the functions without collecting.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Collector -Module 'services' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)
    $cache = @{}

    $services = Invoke-Source -Context $ctx -Source 'Win32_Service' -AsList -ScriptBlock {
        Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Sort-Object Name | ForEach-Object {
            $info = Get-ImageInfo -CommandLine $_.PathName -Cache $cache
            [ordered]@{
                name         = $_.Name
                displayName  = $_.DisplayName
                state        = $_.State
                startMode    = $_.StartMode
                serviceType  = $_.ServiceType
                account      = Get-AccountClass $_.StartName
                imagePath    = $info.imagePath
                imageExists  = $info.imageExists
                hasArguments = $info.hasArguments
                company      = $info.company
            }
        }
    }

    $drivers = Invoke-Source -Context $ctx -Source 'Win32_SystemDriver' -AsList -ScriptBlock {
        Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | Sort-Object Name | ForEach-Object {
            $info = Get-ImageInfo -CommandLine $_.PathName -Cache $cache
            [ordered]@{
                name        = $_.Name
                displayName = $_.DisplayName
                state       = $_.State
                startMode   = $_.StartMode
                serviceType = $_.ServiceType
                imagePath   = $info.imagePath
                imageExists = $info.imageExists
                company     = $info.company
            }
        }
    }

    # HKCU and the user Startup folder belong to the account the collector
    # runs as (see dns-proxy).
    $autostart = Invoke-Source -Context $ctx -Source 'Run keys' -AsList -ScriptBlock {
        foreach ($k in $RunKeys) {
            if (-not (Test-Path -LiteralPath $k.path)) { continue }
            $key = Get-Item -LiteralPath $k.path -ErrorAction Stop
            $approved = $null
            if ($k.approved -and (Test-Path -LiteralPath $k.approved)) { $approved = Get-Item -LiteralPath $k.approved -ErrorAction Stop }
            foreach ($name in ($key.GetValueNames() | Where-Object { $_ -ne '' } | Sort-Object)) {
                $info = Get-ImageInfo -CommandLine $key.GetValue($name, $null, 'DoNotExpandEnvironmentNames') -Cache $cache
                $enabled = $true
                if ($null -ne $approved) { $enabled = Get-StartupApprovedState $approved.GetValue($name, $null) }
                [ordered]@{
                    name         = Hide-UserProfilePath $name
                    location     = $k.location
                    enabled      = $enabled
                    imagePath    = $info.imagePath
                    imageExists  = $info.imageExists
                    hasArguments = $info.hasArguments
                    company      = $info.company
                }
            }
        }
    }
    $startupFolders = Invoke-Source -Context $ctx -Source 'Startup folders' -AsList -ScriptBlock {
        $shell = $null
        $folders = @(
            @{ path = [Environment]::GetFolderPath('Startup'); location = 'Startup (user)'; approved = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' }
            @{ path = [Environment]::GetFolderPath('CommonStartup'); location = 'Startup (all users)'; approved = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' }
        )
        try {
            foreach ($f in $folders) {
                if (-not $f.path -or -not (Test-Path -LiteralPath $f.path)) { continue }
                $approved = $null
                if (Test-Path -LiteralPath $f.approved) { $approved = Get-Item -LiteralPath $f.approved -ErrorAction Stop }
                foreach ($file in (Get-ChildItem -LiteralPath $f.path -File -Force -ErrorAction Stop | Where-Object { $_.Name -ne 'desktop.ini' } | Sort-Object Name)) {
                    $target = $file.FullName
                    $hasArguments = $false
                    if ($file.Extension -eq '.lnk') {
                        # Reading a shortcut does not change it.
                        if ($null -eq $shell) { $shell = New-Object -ComObject WScript.Shell }
                        $link = $shell.CreateShortcut($file.FullName)
                        $target = $link.TargetPath
                        $hasArguments = [bool]$link.Arguments
                    }
                    $info = Get-ImageInfo -CommandLine ('"' + $target + '"') -Cache $cache
                    $enabled = $true
                    if ($null -ne $approved) { $enabled = Get-StartupApprovedState $approved.GetValue($file.Name, $null) }
                    [ordered]@{
                        name         = Hide-UserProfilePath $file.Name
                        location     = $f.location
                        enabled      = $enabled
                        imagePath    = $info.imagePath
                        imageExists  = $info.imageExists
                        hasArguments = $hasArguments
                        company      = $info.company
                    }
                }
            }
        }
        finally {
            if ($null -ne $shell) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
        }
    }
    $autostartAll = $null
    if ($null -ne $autostart -or $null -ne $startupFolders) {
        $autostartAll = @(@($autostart | Where-Object { $null -ne $_ }) + @($startupFolders | Where-Object { $null -ne $_ }))
    }

    # Third-party tasks in full; Microsoft's own (\Microsoft\...) only counted:
    # hundreds of them, rarely relevant, and their list is the same everywhere.
    $tasks = $null
    $rawTasks = Invoke-Source -Context $ctx -Source 'Get-ScheduledTask' -AsList -ScriptBlock {
        Get-ScheduledTask -ErrorAction Stop
    }
    if ($null -ne $rawTasks) {
        $microsoft = @($rawTasks | Where-Object { $_.TaskPath -like '\Microsoft\*' })
        $tasks = [ordered]@{
            thirdParty = @($rawTasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Sort-Object TaskPath, TaskName | ForEach-Object { ConvertTo-TaskEntry -Task $_ -Cache $cache })
            microsoft  = [ordered]@{
                total   = $microsoft.Count
                byState = @($microsoft | Group-Object { [string]$_.State } | Sort-Object Name | ForEach-Object { [ordered]@{ state = $_.Name; count = $_.Count } })
            }
        }
    }

    # NDIS lightweight filters: NetService-class components with filter media
    # types or a filter type (third-party INFs set FilterType/FilterRunType;
    # inbox Microsoft filters only FilterMediaTypes). Bindings give the
    # localized name and on how many adapters the filter is enabled.
    $bindings = Invoke-Source -Context $ctx -Source 'Get-NetAdapterBinding' -AsList -ScriptBlock {
        Get-NetAdapterBinding -IncludeHidden -AllBindings
    }
    $ndisFilters = Invoke-Source -Context $ctx -Source 'NetService class' -AsList -ScriptBlock {
        $byComponent = @{}
        foreach ($b in @($bindings)) {
            if ($null -eq $b) { continue }
            if (-not $byComponent.ContainsKey($b.ComponentID)) { $byComponent[$b.ComponentID] = [System.Collections.Generic.List[object]]::new() }
            $byComponent[$b.ComponentID].Add($b)
        }
        foreach ($item in (Get-ChildItem -LiteralPath $NetServiceClassKey -ErrorAction Stop)) {
            $componentId = $item.GetValue('ComponentId', $null)
            if (-not $componentId) { continue }
            $ndiPath = Join-Path $item.PSPath 'Ndi'
            $ifPath = Join-Path $ndiPath 'Interfaces'
            $ndi = if (Test-Path -LiteralPath $ndiPath) { Get-Item -LiteralPath $ndiPath } else { $null }
            $interfaces = if (Test-Path -LiteralPath $ifPath) { Get-Item -LiteralPath $ifPath } else { $null }
            $filterType = if ($null -ne $ndi) { $ndi.GetValue('FilterType', $null) } else { $null }
            $mediaTypes = if ($null -ne $interfaces) { $interfaces.GetValue('FilterMediaTypes', $null) } else { $null }
            if ($null -eq $filterType -and $null -eq $mediaTypes) { continue }

            $runType = if ($null -ne $ndi) { $ndi.GetValue('FilterRunType', $null) } else { $null }
            $own = if ($byComponent.ContainsKey($componentId)) { $byComponent[$componentId] } else { @() }
            $displayName = @($own | ForEach-Object { $_.DisplayName } | Where-Object { $_ -and $_ -notmatch '^@' } | Select-Object -First 1)
            $description = $item.GetValue('Description', $null)
            [ordered]@{
                componentId     = $componentId
                displayName     = if ($displayName.Count) { $displayName[0] } elseif ($description -and $description -notmatch '^@') { $description } else { $null }
                service         = if ($null -ne $ndi) { $ndi.GetValue('Service', $null) } else { $null }
                filterClass     = if ($null -ne $ndi) { $ndi.GetValue('FilterClass', $null) } else { $null }
                filterType      = if ($null -ne $filterType -and $FilterTypeNames.ContainsKey([int]$filterType)) { $FilterTypeNames[[int]$filterType] } else { $null }
                filterRunType   = if ($null -ne $runType -and $FilterRunTypeNames.ContainsKey([int]$runType)) { $FilterRunTypeNames[[int]$runType] } else { $null }
                bindingsTotal   = @($own).Count
                bindingsEnabled = @($own | Where-Object { $_.Enabled }).Count
            }
        }
    }
    if ($null -ne $ndisFilters) { $ndisFilters = @($ndisFilters | Sort-Object { $_['componentId'] }) }

    [ordered]@{
        services       = $services
        drivers        = $drivers
        autostart      = $autostartAll
        scheduledTasks = $tasks
        ndisFilters    = $ndisFilters
    }
}
