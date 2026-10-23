# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
#
# Tests for collectors/TunnelEye.Common.psm1. Run: Invoke-Pester tests\collectors

Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
Import-Module (Join-Path (Get-RepoRoot) 'collectors\TunnelEye.Common.psm1') -Force

function Get-PipelineValue { 42 }

Describe 'ConvertTo-CollectorJson' {
    It 'writes enums as strings' {
        ConvertTo-CollectorJson ([ordered]@{ d = [DayOfWeek]::Monday }) | Should BeExactly '{"d":"Monday"}'
    }
    It 'writes dates as ISO 8601 UTC with milliseconds' {
        $utc = [datetime]::SpecifyKind([datetime]'2026-01-02 03:04:05.678', 'Utc')
        ConvertTo-CollectorJson ([ordered]@{ t = $utc }) | Should BeExactly '{"t":"2026-01-02T03:04:05.678Z"}'
    }
    It 'keeps single-element and empty arrays as arrays' {
        $one = @(Get-PipelineValue)
        ConvertTo-CollectorJson ([ordered]@{ one = $one; none = @() }) | Should BeExactly '{"one":[42],"none":[]}'
    }
    It 'serializes pipeline-wrapped values, PSCustomObject and New-Object collections' {
        $data = [ordered]@{
            v   = (Get-PipelineValue)
            obj = [pscustomobject]@{ a = 1; nested = [pscustomobject]@{ b = @('x') } }
            od  = New-Object System.Collections.Specialized.OrderedDictionary
            ht  = @{ k = (Get-PipelineValue) }
        }
        ConvertTo-CollectorJson $data | Should BeExactly '{"v":42,"obj":{"a":1,"nested":{"b":["x"]}},"od":{},"ht":{"k":42}}'
    }
    It 'replaces NaN and Infinity with null' {
        ConvertTo-CollectorJson ([ordered]@{ a = [double]::NaN; b = [double]::PositiveInfinity }) | Should BeExactly '{"a":null,"b":null}'
    }
    It 'writes byte arrays as hex and drops SecureString' {
        $secure = New-Object System.Security.SecureString
        ConvertTo-CollectorJson ([ordered]@{ b = [byte[]](1, 255); s = $secure }) | Should BeExactly '{"b":"01ff","s":null}'
    }
    It 'writes timespans as milliseconds' {
        ConvertTo-CollectorJson ([ordered]@{ t = [timespan]::FromSeconds(1.5) }) | Should BeExactly '{"t":1500}'
    }
    It 'round-trips non-ASCII text' {
        $json = ConvertTo-CollectorJson ([ordered]@{ s = "Pr$([char]0x044F)mo" })
        (ConvertFrom-CollectorJson $json)['s'] | Should BeExactly "Pr$([char]0x044F)mo"
    }
}

Describe 'Get-ErrorKind' {
    It 'maps <exception> to <kind>' -TestCases @(
        @{ exception = [UnauthorizedAccessException]'x'; kind = 'AccessDenied' }
        @{ exception = [TimeoutException]'x'; kind = 'Timeout' }
        @{ exception = [NotSupportedException]'x'; kind = 'NotSupported' }
        @{ exception = [IO.FileNotFoundException]'x'; kind = 'NotFound' }
        @{ exception = (New-Object ComponentModel.Win32Exception 5); kind = 'AccessDenied' }
        @{ exception = [InvalidOperationException]'x'; kind = 'Exception' }
        @{ exception = (New-Object Exception 'outer', ([UnauthorizedAccessException]'inner')); kind = 'AccessDenied' }
    ) {
        param($exception, $kind)
        Get-ErrorKind $exception | Should Be $kind
    }
    It 'maps an unknown command to NotSupported' {
        try { Get-NoSuchCommandXyz } catch { $record = $_ }
        Get-ErrorKind $record | Should Be 'NotSupported'
    }
}

Describe 'Invoke-Source' {
    BeforeEach { $ctx = New-CollectorContext -Module 'test' -Version '1.0.0' }

    It 'returns a single value' {
        Invoke-Source -Context $ctx -Source 's' -ScriptBlock { 7 } | Should Be 7
        $ctx.Errors.Count | Should Be 0
    }
    It '-AsList returns an array for one and zero items' {
        $one = Invoke-Source -Context $ctx -Source 's' -AsList -ScriptBlock { 7 }
        $none = Invoke-Source -Context $ctx -Source 's' -AsList -ScriptBlock { }
        , $one | Should BeOfType [object[]]
        $one.Count | Should Be 1
        , $none | Should BeOfType [object[]]
        $none.Count | Should Be 0
    }
    It 'records a terminating error and returns null' {
        $r = Invoke-Source -Context $ctx -Source 'bad' -AsList -ScriptBlock { throw [UnauthorizedAccessException]'denied' }
        $r | Should BeNullOrEmpty
        $null -eq $r | Should Be $true
        $ctx.Errors.Count | Should Be 1
        $ctx.Errors[0].source | Should Be 'bad'
        $ctx.Errors[0].kind | Should Be 'AccessDenied'
        $ctx.Errors[0].fatal | Should Be $false
    }
    It 'records non-terminating errors and keeps partial output' {
        $r = Invoke-Source -Context $ctx -Source 'soft' -AsList -ScriptBlock { 1; Write-Error 'soft fail'; 2 }
        ($r -join ',') | Should Be '1,2'
        $ctx.Errors.Count | Should Be 1
        $ctx.Errors[0].message | Should Be 'soft fail'
    }
    It 'skips admin-only sources when not elevated' {
        $ctx.Elevated = $false
        $script:ran = $false
        $r = Invoke-Source -Context $ctx -Source 'admin' -RequiresAdmin -ScriptBlock { $script:ran = $true; 1 }
        $null -eq $r | Should Be $true
        $script:ran | Should Be $false
        $ctx.Errors[0].kind | Should Be 'AccessDenied'
    }
}

Describe 'Invoke-AllowNotFound' {
    It 'passes output through' {
        (@(Invoke-AllowNotFound { 1; 2 }) -join ',') | Should Be '1,2'
    }
    It 'turns ObjectNotFound into empty output' {
        $r = @(Invoke-AllowNotFound { Write-Error -Message 'none' -Category ObjectNotFound -ErrorAction Stop })
        $r.Count | Should Be 0
    }
    It 'rethrows other errors' {
        { Invoke-AllowNotFound { throw [UnauthorizedAccessException]'denied' } } | Should Throw 'denied'
    }
}

Describe 'Invoke-NativeCommand' {
    BeforeEach { $ctx = New-CollectorContext -Module 'test' -Version '1.0.0' }

    It 'captures stdout and exit code' {
        $r = Invoke-NativeCommand -Context $ctx -Source 'cmd' -FilePath 'cmd.exe' -ArgumentList '/c', 'echo hello'
        $r.exitCode | Should Be 0
        $r.stdout.Trim() | Should Be 'hello'
        $ctx.Errors.Count | Should Be 0
    }
    It 'records a non-zero exit code but returns output' {
        $r = Invoke-NativeCommand -Context $ctx -Source 'cmd' -FilePath 'cmd.exe' -ArgumentList '/c', 'echo oops & exit 3'
        $r.exitCode | Should Be 3
        $ctx.Errors.Count | Should Be 1
        $ctx.Errors[0].message | Should Match 'Exit code 3'
    }
    It 'accepts custom success exit codes' {
        $null = Invoke-NativeCommand -Context $ctx -Source 'cmd' -FilePath 'cmd.exe' -ArgumentList '/c', 'exit 1' -SuccessExitCodes 0, 1
        $ctx.Errors.Count | Should Be 0
    }
    It 'times out and kills the process' {
        $r = Invoke-NativeCommand -Context $ctx -Source 'slow' -FilePath 'powershell.exe' -ArgumentList '-NoProfile', '-Command', 'Start-Sleep 10' -TimeoutSec 1
        $null -eq $r | Should Be $true
        $ctx.Errors[0].kind | Should Be 'Timeout'
    }
    It 'reports a missing tool as NotFound' {
        $r = Invoke-NativeCommand -Context $ctx -Source 'missing' -FilePath 'no-such-tool-xyz.exe'
        $null -eq $r | Should Be $true
        $ctx.Errors[0].kind | Should Be 'NotFound'
    }
    It 'skips admin-only commands when not elevated' {
        $ctx.Elevated = $false
        $r = Invoke-NativeCommand -Context $ctx -Source 'admin' -FilePath 'cmd.exe' -ArgumentList '/c', 'echo x' -RequiresAdmin
        $null -eq $r | Should Be $true
        $ctx.Errors[0].kind | Should Be 'AccessDenied'
    }
}

Describe 'ConvertFrom-NativeBytes' {
    $text = "Pr$([char]0x044F)moi dostup"   # contains Cyrillic 'ya'
    It 'decodes ANSI 1251 bytes' {
        ConvertFrom-NativeBytes -Bytes ([Text.Encoding]::GetEncoding(1251).GetBytes($text)) | Should BeExactly $text
    }
    It 'decodes OEM 866 bytes' {
        ConvertFrom-NativeBytes -Bytes ([Text.Encoding]::GetEncoding(866).GetBytes($text)) | Should BeExactly $text
    }
    It 'decodes UTF-8 bytes' {
        ConvertFrom-NativeBytes -Bytes ([Text.Encoding]::UTF8.GetBytes($text)) | Should BeExactly $text
    }
    It 'decodes UTF-16LE without BOM' {
        ConvertFrom-NativeBytes -Bytes ([Text.Encoding]::Unicode.GetBytes($text)) | Should BeExactly $text
    }
    It 'returns empty string for no bytes' {
        ConvertFrom-NativeBytes -Bytes (New-Object byte[] 0) | Should BeExactly ''
    }
}

Describe 'Complete-Collector' {
    BeforeEach { $ctx = New-CollectorContext -Module 'test' -Version '1.2.3' }

    It 'builds a valid ok envelope' {
        $env = ConvertFrom-CollectorJson (ConvertTo-CollectorJson (Complete-Collector -Context $ctx -Data ([ordered]@{ a = 1 })))
        (Get-EnvelopeProblems -Envelope $env -Module 'test').Count | Should Be 0
        $env['status'] | Should Be 'ok'
        $env['version'] | Should Be '1.2.3'
    }
    It 'is partial when data has errors' {
        Add-CollectorError -Context $ctx -Source 's' -Kind Exception -Message 'x'
        (Complete-Collector -Context $ctx -Data ([ordered]@{ a = 1 })).status | Should Be 'partial'
    }
    It 'is failed without data' {
        (Complete-Collector -Context $ctx -Data $null).status | Should Be 'failed'
    }
    It 'is skipped with a reason and no data' {
        $env = Complete-Collector -Context $ctx -Data ([ordered]@{ a = 1 }) -Skipped -SkipReason 'n/a'
        $env.status | Should Be 'skipped'
        $null -eq $env.data | Should Be $true
        $env.errors[0].message | Should Be 'n/a'
    }
}

Describe 'Get-RegistryValue' {
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    It 'reads an existing value' {
        Get-RegistryValue -Path $cv -Name 'CurrentBuild' | Should Match '^\d+$'
    }
    It 'returns null for a missing value' {
        $null -eq (Get-RegistryValue -Path $cv -Name 'NoSuchValueXyz') | Should Be $true
    }
    It 'returns null for a missing key' {
        $null -eq (Get-RegistryValue -Path 'HKLM:\SOFTWARE\NoSuchKeyXyz' -Name 'x') | Should Be $true
    }
}

Describe 'Get-NonCamelCaseKeys' {
    It 'finds bad keys at any depth' {
        $data = ConvertFrom-CollectorJson '{"good":1,"Bad":2,"list":[{"also_bad":3}]}'
        (Get-NonCamelCaseKeys -Node $data) -join ';' | Should Be 'data.Bad;data.list[0].also_bad'
    }
}
