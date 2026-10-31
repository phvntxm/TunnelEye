# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param([ValidateSet('ru', 'en')][string]$Language = 'ru')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$resourceName = if ($Language -eq 'en') { 'Safety.en.resx' } else { 'Safety.resx' }
[xml]$resources = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $resourceName), [Text.Encoding]::UTF8)
$messages = @{}
foreach ($entry in $resources.root.data) { $messages[[string]$entry.name] = [string]$entry.value }
try {
    $current = & git -C $root config --get core.hooksPath
    if ($LASTEXITCODE -gt 1) { throw 'Cannot read Git configuration.' }
    if ($current -and $current -ne '.githooks') { Write-Host $messages.InstallConflict; exit 1 }
    if (!$current) {
        $defaultHook = & git -C $root rev-parse --git-path hooks/pre-commit
        if ($LASTEXITCODE -ne 0) { throw 'Cannot locate Git hooks.' }
        if (![IO.Path]::IsPathRooted($defaultHook)) { $defaultHook = Join-Path $root $defaultHook }
        if (Test-Path -LiteralPath $defaultHook) { Write-Host $messages.InstallConflict; exit 1 }
    }
    & git -C $root config --local core.hooksPath .githooks
    if ($LASTEXITCODE -ne 0) { throw 'Cannot configure Git hook.' }
    Write-Host $messages.Installed
    exit 0
} catch { Write-Host $messages.Failed; exit 2 }
