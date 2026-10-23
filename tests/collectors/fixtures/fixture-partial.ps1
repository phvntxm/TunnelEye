# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Test fixture collector for the orchestrator tests. One source fails, one needs admin.

param([string] $OutFile)
Import-Module (Join-Path $PSScriptRoot '..\..\..\collectors\TunnelEye.Common.psm1') -Force

Invoke-Collector -Module 'fixture-partial' -Version '1.0.0' -OutFile $OutFile -ScriptBlock {
    param($ctx)
    $ctx.Elevated = $false
    [ordered]@{
        good   = Invoke-Source -Context $ctx -Source 'good' -ScriptBlock { 1 }
        broken = Invoke-Source -Context $ctx -Source 'broken' -ScriptBlock { throw 'boom' }
        admin  = Invoke-Source -Context $ctx -Source 'admin' -RequiresAdmin -ScriptBlock { 2 }
    }
}
