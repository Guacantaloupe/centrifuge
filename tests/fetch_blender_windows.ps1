param(
    [string]$Destination = "corpus\windows\blender-4.2.0",
    [switch]$KeepArchive
)

$ErrorActionPreference = "Stop"
$url = "https://download.blender.org/release/Blender4.2/blender-4.2.0-windows-x64.zip"
$expected = "b6e72874f8cb5c4ed77f9b03d7f1fde851b9455a7ff02a1e1119c876318ebc65"
$destinationPath = [System.IO.Path]::GetFullPath($Destination)
$parent = Split-Path -Parent $destinationPath
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$archive = Join-Path $parent "blender-4.2.0-windows-x64.zip"

Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
if ($actual -ne $expected) {
    throw "Blender archive SHA-256 mismatch: expected $expected, got $actual"
}
New-Item -ItemType Directory -Force -Path $destinationPath | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath $destinationPath -Force
if (-not $KeepArchive) {
    Remove-Item -LiteralPath $archive
}
$binary = Get-ChildItem -LiteralPath $destinationPath -Recurse -Filter blender.exe |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $binary) {
    throw "Downloaded archive did not contain blender.exe"
}
Write-Output $binary
