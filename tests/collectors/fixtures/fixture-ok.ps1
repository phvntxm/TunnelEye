# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Test fixture collector for the orchestrator tests. Produces a valid 'ok' envelope.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot '..\..\..\collectors\TunnelEye.Common.psm1') -Force

Invoke-Collector -Module 'fixture-ok' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)
    [ordered]@{
        single = @(Invoke-Source -Context $ctx -Source 'single' -AsList -ScriptBlock { 'one' })
        day    = [DayOfWeek]::Friday
    }
}
