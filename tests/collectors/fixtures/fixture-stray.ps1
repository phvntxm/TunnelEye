# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Test fixture collector for the orchestrator tests. Leaks pipeline output instead of returning a dictionary.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot '..\..\..\collectors\TunnelEye.Common.psm1') -Force

Invoke-Collector -Module 'fixture-stray' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)
    'stray'
    [ordered]@{ a = 1 }
}
