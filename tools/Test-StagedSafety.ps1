# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
# Inspect index blobs, never the potentially different working-tree contents.
[CmdletBinding()]
param(
    [string]$RepositoryPath = (Get-Location).Path,
    [switch]$AllTracked,
    [ValidateSet('ru', 'en')][string]$Language = 'ru'
)
$ErrorActionPreference = 'Stop'
$resourceName = if ($Language -eq 'en') { 'Safety.en.resx' } else { 'Safety.resx' }
[xml]$resources = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $resourceName), [Text.Encoding]::UTF8)
$messages = @{}
foreach ($entry in $resources.root.data) { $messages[[string]$entry.name] = [string]$entry.value }
function Invoke-GitBytes([string]$Arguments) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = 'git'
    $start.Arguments = $Arguments
    $start.WorkingDirectory = [IO.Path]::GetFullPath($RepositoryPath)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $buffer = New-Object IO.MemoryStream
    try {
        [void]$process.Start()
        $errors = $process.StandardError.ReadToEndAsync()
        $process.StandardOutput.BaseStream.CopyTo($buffer)
        $process.WaitForExit()
        [void]$errors.Result
        if ($process.ExitCode -ne 0) { throw 'Git command failed.' }
        return ,$buffer.ToArray()
    } finally { $buffer.Dispose(); $process.Dispose() }
}
function Get-GitText([string]$Arguments) {
    [Text.Encoding]::UTF8.GetString((Invoke-GitBytes $Arguments))
}
$violations = New-Object 'System.Collections.Generic.List[object]'
function Reject([string]$Path, [string]$Rule) {
    # Never emit the matched value, a line of file contents or Git stderr.
    $safePath = [regex]::Replace($Path, '[\x00-\x1f\x7f]', '?')
    $violations.Add(@($safePath, $Rule))
}
try {
    $selected = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    if (-not $AllTracked) {
        foreach ($path in (Get-GitText 'diff --cached --name-only --diff-filter=ACMR -z').Split([char]0)) {
            if ($path) { [void]$selected.Add($path) }
        }
    }
    $entries = (Get-GitText 'ls-files --stage -z').Split([char]0)
    $checked = 0
    foreach ($entry in $entries) {
        if (!$entry) { continue }
        if ($entry -notmatch '(?s)^(\d{6}) ([0-9a-f]{40,64}) ([0-3])\t(.*)$') { throw 'Invalid index entry.' }
        $mode, $oid, $stage, $path = $Matches[1], $Matches[2], $Matches[3], $Matches[4]
        if ($stage -ne '0') { Reject $path 'unmerged'; continue }
        if (!$AllTracked -and !$selected.Contains($path)) { continue }
        $checked++
        if ($path -match '[\x00-\x1f\x7f]') { Reject $path 'path'; continue }
        if (($path -match '(?i)(^|/)\.local(/|$)' -or $path -match '(?i)^(output|snapshots|exports|reports|logs|secrets|credentials)/') -and $path -notmatch '^tests/snapshots/') { Reject $path 'private-path'; continue }
        if ($path -match '(?i)(^|/)(\.env(?:\..*)?|[^/]+\.env|id_(rsa|dsa|ecdsa|ed25519))$' -and $path -notmatch '(^|/)\.env\.example$') { Reject $path 'secret-file'; continue }
        if ($path -match '(?i)\.(key|pem|pfx|p12|jks|keystore|pcap|pcapng|etl|dmp|dump|log)$') { Reject $path 'secret-file'; continue }
        if ($mode -ne '100644' -and $mode -ne '100755') { Reject $path 'special-file'; continue }
        $size = [long](Get-GitText ("cat-file -s " + $oid)).Trim()
        if ($size -gt 5MB) { Reject $path 'large-file'; continue }
        $bytes = Invoke-GitBytes ("cat-file blob " + $oid)
        if ($bytes -contains 0) { Reject $path 'binary-file'; continue }
        $text = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
        $patterns = @{
            'private-key' = '-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----'
            'access-token' = '(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,})'
            'credential-url' = '(?i)https?://[^/\s:@]+:[^/\s@]+@'
            'user-path' = '(?i)[a-z]:\\Users\\(?!Public(?:\\|$)|Default(?:\\|$)|PrivateUser(?:\\|$)|ExampleUser(?:\\|$)|TestUser(?:\\|$)|someone(?:\\|$)|USER-\d+(?:\\|$)|<)[^\\\s"'']+\\'
            'secret-json' = '(?i)["''](?:password|token|secret|api[_-]?key|client_secret|access_token)["'']\s*:\s*["''][A-Za-z0-9+/=_-]{8,}["'']'
            'secret-assignment' = '(?im)^\s*(?:export\s+)?(?:[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)|password|token|secret|api_key)\s*=\s*["'']?([A-Za-z0-9+/=_-]{16,})["'']?\s*$'
        }
        foreach ($rule in $patterns.Keys) {
            foreach ($match in [regex]::Matches($text, $patterns[$rule], [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2))) {
                # Existing parser tests intentionally exercise one invented credential.
                # This exempts that exact value in two files, not all tests or URLs.
                $knownParserExample = $rule -eq 'credential-url' -and $path -cmatch '^tests/collectors/(Connectivity|DnsProxy)\.Tests\.ps1$' -and $match.Value -ceq ('http://user:' + 'secret@')
                if (!$knownParserExample) { Reject $path $rule; break }
            }
        }
        # Reports and captures stay local even if renamed or force-added.
        if ($text -match '(?is)^\s*<!doctype\s+html.*<title>\s*TunnelEye') { Reject $path 'diagnostic-data' }
        if ($text.TrimStart().StartsWith('{')) {
            try { $json = ConvertFrom-Json -InputObject $text -ErrorAction Stop } catch { $json = $null }
            if ($null -ne $json -and $json.schema -match '^tunneleye\.(snapshot|module|analysis|report)/') {
                $synthetic = $path -cmatch '^tests/snapshots/[^/]+\.json$' -and $json.schema -eq 'tunneleye.snapshot/1' -and $json.snapshotId -match '^00000000-0000-4000-8000-\d{12}$'
                if (!$synthetic) { Reject $path 'diagnostic-data' }
            }
        }
    }
    if ($violations.Count -gt 0) {
        Write-Host $messages.Blocked
        foreach ($item in $violations) { Write-Host ('  {0}: {1}' -f $item[0], $messages[$item[1]]) }
        Write-Host $messages.Help
        exit 1
    }
    Write-Host ($messages.Passed -f $checked)
    exit 0
} catch {
    Write-Host $messages.Failed
    exit 2
}
