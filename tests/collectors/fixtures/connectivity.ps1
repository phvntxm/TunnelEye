# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Test fixture collector for the orchestrator tests: stands in for the real
# 'connectivity' module and reports whether it received -AllowExternal.

param([string] $OutFile, [switch] $AllowExternal)
Import-Module (Join-Path $PSScriptRoot '..\..\..\collectors\TunnelEye.Common.psm1') -Force

Invoke-Collector -Module 'connectivity' -Version '0.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)
    [ordered]@{ externalAllowed = [bool]$AllowExternal }
}
