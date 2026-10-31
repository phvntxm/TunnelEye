# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
# Expand a synthetic snapshot overlay for manual CLI checks.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Overlay,
    [Parameter(Mandatory = $true, Position = 1)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Web.Extensions
$serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$serializer.MaxJsonLength = [int]::MaxValue
$serializer.RecursionLimit = 256
$active = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
function Merge-Tree($Target, $Patch) {
    foreach ($key in $Patch.Keys) {
        if ($Patch[$key] -is [System.Collections.IDictionary] -and $Target[$key] -is [System.Collections.IDictionary]) {
            Merge-Tree $Target[$key] $Patch[$key]
        } else { $Target[$key] = $Patch[$key] }
    }
}
function Read-Tree([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $active.Add($full)) { throw 'Overlay cycle detected.' }
    try {
        $tree = $serializer.DeserializeObject([IO.File]::ReadAllText($full, [Text.Encoding]::UTF8))
        if ($tree['schema'] -ne 'tunneleye.test-overlay/1') { return ,$tree }
        $baseName = [string]$tree['base']
        if ($baseName -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Invalid overlay base name.' }
        $base = Read-Tree (Join-Path ([IO.Path]::GetDirectoryName($full)) ($baseName + '.json'))
        if ($tree['patch'] -isnot [System.Collections.IDictionary]) { throw 'Overlay patch must be an object.' }
        Merge-Tree $base $tree['patch']
        return ,$base
    } finally { [void]$active.Remove($full) }
}
$result = Read-Tree $Overlay
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), $serializer.Serialize($result), (New-Object Text.UTF8Encoding($false)))
