param(
    [string]$Destination = "corpus\windows\krita-6.0.3",
    [switch]$KeepArchive
)

$ErrorActionPreference = "Stop"
$url = "https://download.kde.org/stable/krita/6.0.3/krita-x64-6.0.3.zip"
$expectedArchive = "c0fe0292a4a9bb5b145b0239b92c5b11fc93915dab37bed6d33b6648ad03578b"
$expectedBinary = "e4e5d5caeb14dd4c18bfd9ff52e20c37ad8339b4b18f867c2723509890f203ae"
$destinationPath = [System.IO.Path]::GetFullPath($Destination)
$parent = Split-Path -Parent $destinationPath
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$archive = Join-Path $parent "krita-x64-6.0.3.zip"

Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
$archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
if ($archiveHash -ne $expectedArchive) {
    throw "Krita archive SHA-256 mismatch: expected $expectedArchive, got $archiveHash"
}
New-Item -ItemType Directory -Force -Path $destinationPath | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath $destinationPath -Force
$binary = Get-ChildItem -LiteralPath $destinationPath -Recurse -Filter libkritaui.dll |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $binary) {
    throw "Downloaded archive did not contain libkritaui.dll"
}
$binaryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant()
if ($binaryHash -ne $expectedBinary) {
    throw "Krita DLL SHA-256 mismatch: expected $expectedBinary, got $binaryHash"
}
if (-not $KeepArchive) {
    Remove-Item -LiteralPath $archive
}
Write-Output $binary
