# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
# Integration tests use isolated repositories and invented secret values.
Describe 'Staged safety guard' {
    $projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $guard = Join-Path $projectRoot 'tools\Test-StagedSafety.ps1'
    BeforeEach {
        $repo = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $repo | Out-Null
        & git -C $repo init -q
    }
    function Stage-Text([string]$Name, [string]$Text) {
        $path = Join-Path $repo $Name
        New-Item -ItemType Directory -Force ([IO.Path]::GetDirectoryName($path)) | Out-Null
        [IO.File]::WriteAllText($path, $Text, (New-Object Text.UTF8Encoding($false)))
        & git -C $repo add -- $Name
    }
    function Invoke-Safety {
        $output = & powershell.exe -NoProfile -File $guard -RepositoryPath $repo -Language en 2>&1
        @{ Code = $LASTEXITCODE; Text = ($output -join "`n") }
    }
    It 'allows ordinary source, a blank env template and documentation IPs' {
        Stage-Text 'source.txt' 'Example address 192.0.2.1; password is not stored.'
        Stage-Text '.env.example' 'API_KEY='
        (Invoke-Safety).Code | Should Be 0
    }
    It 'blocks a staged token even when the working file was cleaned' {
        $fake = 'gh' + 'p_' + ('a' * 36)
        Stage-Text 'source.txt' $fake
        [IO.File]::WriteAllText((Join-Path $repo 'source.txt'), 'clean')
        $result = Invoke-Safety
        $result.Code | Should Be 1
        $result.Text | Should Not Match ([regex]::Escape($fake))
    }
    It 'ignores an unstaged secret when the staged contents are safe' {
        Stage-Text 'source.txt' 'clean'
        [IO.File]::WriteAllText((Join-Path $repo 'source.txt'), ('gh' + 'p_' + ('b' * 36)))
        (Invoke-Safety).Code | Should Be 0
    }
    It 'blocks forced private paths and secret filenames' {
        Stage-Text '.local/notes.txt' 'private'
        Stage-Text '.env' 'VALUE=local'
        Stage-Text 'signing.pfx' 'not a real certificate'
        (Invoke-Safety).Code | Should Be 1
    }
    It 'blocks snapshots outside the synthetic fixtures' {
        Stage-Text 'renamed.txt' '{"schema":"tunneleye.snapshot/1","snapshotId":"real-machine-id"}'
        (Invoke-Safety).Code | Should Be 1
    }
    It 'does not trust a real snapshot copied into the fixture directory' {
        Stage-Text 'tests/snapshots/copied.json' '{"schema":"tunneleye.snapshot/1","snapshotId":"real-machine-id"}'
        (Invoke-Safety).Code | Should Be 1
    }
    It 'allows a declared synthetic snapshot' {
        Stage-Text 'tests/snapshots/clean.json' '{"schema":"tunneleye.snapshot/1","snapshotId":"00000000-0000-4000-8000-000000000001"}'
        (Invoke-Safety).Code | Should Be 0
    }
    It 'blocks reports even when their contents are masked' {
        Stage-Text 'example.json' '{"schema":"tunneleye.report/1","masked":true}'
        (Invoke-Safety).Code | Should Be 1
    }
    It 'blocks a private key without printing its marker' {
        $fake = '-----BEGIN ' + 'PRIVATE KEY-----'
        Stage-Text 'data.txt' $fake
        $result = Invoke-Safety
        $result.Code | Should Be 1
        $result.Text | Should Not Match ([regex]::Escape($fake))
    }
    It 'blocks concrete profile paths but permits explicit test placeholders' {
        Stage-Text 'notes.txt' ('C:\' + 'Users\InventedPerson\Documents')
        (Invoke-Safety).Code | Should Be 1
    }
    It 'handles a filename with spaces and non-ASCII characters' {
        Stage-Text 'example directory/тест.txt' 'ordinary text'
        (Invoke-Safety).Code | Should Be 0
    }
    It 'does not exempt other credentials in a legacy parser test' {
        Stage-Text 'tests/collectors/DnsProxy.Tests.ps1' ('https://invented:' + 'invented-password@host.invalid')
        (Invoke-Safety).Code | Should Be 1
    }
    It 'rejects secret assignments in the env template' {
        Stage-Text '.env.example' ('API_KEY=' + ('q' * 24))
        (Invoke-Safety).Code | Should Be 1
    }
    It 'permits source files under Reports rather than treating them as exports' {
        Stage-Text 'src/Argus.Core/Reports/Example.cs' '// source'
        (Invoke-Safety).Code | Should Be 0
    }
    It 'blocks a password in JSON without displaying it' {
        $fake = 'invented' + '-password'
        Stage-Text 'config.json' ('{"password":"' + $fake + '"}')
        $result = Invoke-Safety
        $result.Code | Should Be 1
        $result.Text | Should Not Match ([regex]::Escape($fake))
    }
    It 'makes the Git hook reject a commit' {
        $toolDir = Join-Path $repo 'tools'
        New-Item -ItemType Directory $toolDir | Out-Null
        Copy-Item -LiteralPath $guard -Destination $toolDir
        Copy-Item (Join-Path $projectRoot 'tools\Safety*.resx') $toolDir
        Stage-Text '.env' 'VALUE=local'
        & git -C $repo config core.hooksPath (Join-Path $projectRoot '.githooks')
        $hookOutput = & git -C $repo -c user.name=Test -c user.email=test@example.invalid commit -m 'Blocked test' 2>&1
        $LASTEXITCODE | Should Not Be 0
        $result = & git -C $repo rev-list --all --count 2>$null
        $result | Should Be 0
        ($hookOutput -join "`n") | Should Match 'Коммит остановлен'
        & git -C $repo rm --cached -- .env 2>$null | Out-Null
        Stage-Text 'source.txt' 'clean'
        $null = & git -C $repo -c user.name=Test -c user.email=test@example.invalid commit -m 'Safe test' 2>&1
        $LASTEXITCODE | Should Be 0
        (& git -C $repo rev-list --all --count) | Should Be 1
    }
}
