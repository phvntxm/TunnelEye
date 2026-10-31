# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
Describe 'Expand-Overlay' {
    $scriptPath = Join-Path $PSScriptRoot '..\Expand-Overlay.ps1'
    It 'expands nested overlays into a snapshot with replaced arrays' {
        $out = Join-Path $TestDrive 'expanded.json'
        & $scriptPath (Join-Path $PSScriptRoot '..\snapshots\vpn-conflict.json') $out
        $tree = Get-Content $out -Raw | ConvertFrom-Json
        $tree.schema | Should Be 'tunneleye.snapshot/1'
        @($tree.modules.adapters.data.adapters).Count | Should Be 4
        @($tree.modules.routing.data.routes).Count | Should Be 5
        $tree.modules.system.status | Should Be 'ok'
    }
    It 'rejects cycles before writing output' {
        $inputPath = Join-Path $TestDrive 'cycle.json'
        $out = Join-Path $TestDrive 'cycle-out.json'
        Set-Content $inputPath '{"schema":"tunneleye.test-overlay/1","base":"cycle","patch":{}}'
        { & $scriptPath $inputPath $out } | Should Throw
        Test-Path $out | Should Be $false
    }
    It 'rejects a base outside the snapshot directory' {
        $inputPath = Join-Path $TestDrive 'escape.json'
        Set-Content $inputPath '{"schema":"tunneleye.test-overlay/1","base":"../clean","patch":{}}'
        { & $scriptPath $inputPath (Join-Path $TestDrive 'escape-out.json') } | Should Throw
    }
}
