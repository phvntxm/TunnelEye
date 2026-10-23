# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Repository-wide checks for PowerShell sources.

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force

Describe 'PowerShell sources' {
    $root = Get-RepoRoot
    $files = @(Get-ChildItem -Path (Join-Path $root 'collectors'), (Join-Path $root 'tests') -Recurse -Include *.ps1, *.psm1)

    It 'are ASCII-only or start with a UTF-8 BOM (PowerShell 5.1 reads BOM-less files as ANSI)' {
        $bad = foreach ($f in $files) {
            $bytes = [IO.File]::ReadAllBytes($f.FullName)
            $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
            if (-not $hasBom -and @($bytes | Where-Object { $_ -gt 127 }).Count) { $f.Name }
        }
        @($bad) -join ', ' | Should Be ''
    }
    It 'carry the license header' {
        $bad = foreach ($f in $files) {
            if (-not (Select-String -LiteralPath $f.FullName -Pattern 'SPDX-License-Identifier: Apache-2.0' -SimpleMatch -Quiet)) { $f.Name }
        }
        @($bad) -join ', ' | Should Be ''
    }
    It 'parse without syntax errors' {
        $bad = foreach ($f in $files) {
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errors)
            if ($errors) { "$($f.Name): $($errors[0].Message)" }
        }
        @($bad) -join ', ' | Should Be ''
    }
}
