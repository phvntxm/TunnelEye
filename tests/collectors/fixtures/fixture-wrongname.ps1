# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Test fixture collector for the orchestrator tests. Valid envelope with a mismatched module name.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot '..\..\..\collectors\TunnelEye.Common.psm1') -Force

Invoke-Collector -Module 'something-else' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)
    [ordered]@{ a = 1 }
}
