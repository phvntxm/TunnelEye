# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Test fixture collector for the orchestrator tests. Not applicable on this machine.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot '..\..\..\collectors\TunnelEye.Common.psm1') -Force

Invoke-Collector -Module 'fixture-skip' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)
    New-SkipResult 'No such hardware.'
}
