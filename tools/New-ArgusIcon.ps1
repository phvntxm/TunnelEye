# Copyright 2026 phvntxm
# SPDX-License-Identifier: Apache-2.0
# Build a Windows PNG-backed ICO from the original vector; no binary asset in Git.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$DrawingPath, [Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase
$drawing = [Windows.Markup.XamlReader]::Parse([IO.File]::ReadAllText([IO.Path]::GetFullPath($DrawingPath)))
$sizes = @(16,32,48,256)
$images = [Collections.Generic.List[byte[]]]::new()
foreach ($size in $sizes) {
    $visual = New-Object Windows.Media.DrawingVisual
    $context = $visual.RenderOpen()
    try { $context.DrawImage($drawing, (New-Object Windows.Rect(0,0,$size,$size))) } finally { $context.Close() }
    $bitmap = New-Object Windows.Media.Imaging.RenderTargetBitmap($size,$size,96,96,[Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($visual)
    $encoder = New-Object Windows.Media.Imaging.PngBitmapEncoder
    $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $memory = New-Object IO.MemoryStream
    try { $encoder.Save($memory); $images.Add($memory.ToArray()) } finally { $memory.Dispose() }
}
$full = [IO.Path]::GetFullPath($OutputPath)
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($full))
$writer = [IO.BinaryWriter]::new([IO.File]::Create($full))
try {
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i=0; $i -lt $sizes.Count; $i++) {
        $dimension = if ($sizes[$i] -eq 256) { 0 } else { $sizes[$i] }
        $writer.Write([byte]$dimension); $writer.Write([byte]$dimension)
        $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([uint16]1); $writer.Write([uint16]32)
        $writer.Write([uint32]$images[$i].Length); $writer.Write([uint32]$offset)
        $offset += $images[$i].Length
    }
    foreach ($bytes in $images) { $writer.Write([byte[]]$bytes) }
} finally { $writer.Dispose() }
