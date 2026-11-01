# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
# Render the actual WPF visual tree in an invisible off-screen host; no collection.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$SnapshotPath,
    [ValidateSet('ru','en')][string]$Language = 'ru',
    [ValidateRange(0,5)][int]$Tab = 0,
    [ValidateRange(0,100000)][int]$ScrollOffset = 0
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
$root = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $root 'src\TunnelEye.App\bin\Debug\net48'
foreach ($name in 'Argus.Core.dll','OxyPlot.dll','OxyPlot.Wpf.Shared.dll','OxyPlot.Wpf.dll','TunnelEye.exe') {
    [void][Reflection.Assembly]::LoadFrom((Join-Path $bin $name))
}
[Threading.SynchronizationContext]::SetSynchronizationContext((New-Object Windows.Threading.DispatcherSynchronizationContext))
$app = New-Object Windows.Application
$window = New-Object TunnelEye.App.MainWindow
$window.ShowInTaskbar = $false
$window.ShowActivated = $false
$window.Opacity = 0
$window.WindowStartupLocation = [Windows.WindowStartupLocation]::Manual
$window.Left = -20000
$window.Top = -20000
$window.Show()
if ($SnapshotPath) {
    $task = $window.OpenSnapshotAsync([IO.Path]::GetFullPath($SnapshotPath))
    while (!$task.IsCompleted) {
        $frame = New-Object Windows.Threading.DispatcherFrame
        [void][Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke([Windows.Threading.DispatcherPriority]::Background, [Action]{ $frame.Continue = $false })
        [Windows.Threading.Dispatcher]::PushFrame($frame)
        Start-Sleep -Milliseconds 10
    }
    [void]$task.GetAwaiter().GetResult()
}
# Exercise the real language switch and tab selection on the detached visual tree.
$header = $window.Content.Children[0]
$header.Children[1].SelectedIndex = $(if ($Language -eq 'en') { 1 } else { 0 })
$body = $window.Content.Children[$window.Content.Children.Count - 1]
if ($SnapshotPath) { $body.Children[0].SelectedIndex = $Tab }
$visual = $window.Content
$window.UpdateLayout()
[Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Windows.Threading.DispatcherPriority]::ApplicationIdle, [Action]{})
$visual.UpdateLayout()
if ($SnapshotPath -and $ScrollOffset -gt 0) {
    $scroll = $body.Children[0].Items[$Tab].Content
    if ($scroll -is [Windows.Controls.ScrollViewer]) {
        $scroll.ScrollToVerticalOffset($ScrollOffset)
        [Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Windows.Threading.DispatcherPriority]::ApplicationIdle, [Action]{})
        $visual.UpdateLayout()
    }
}
$drawing = New-Object Windows.Media.DrawingVisual
$context = $drawing.RenderOpen()
try {
    $brush = New-Object Windows.Media.VisualBrush($visual)
    $context.DrawRectangle($brush, $null, (New-Object Windows.Rect(0,0,1200,800)))
} finally { $context.Close() }
$bitmap = New-Object Windows.Media.Imaging.RenderTargetBitmap(1200,800,96,96,[Windows.Media.PixelFormats]::Pbgra32)
$bitmap.Render($drawing)
$encoder = New-Object Windows.Media.Imaging.PngBitmapEncoder
$encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
$stream = [IO.File]::Create([IO.Path]::GetFullPath($OutputPath))
try { $encoder.Save($stream) } finally { $stream.Dispose(); $window.Close(); $app.Shutdown() }
