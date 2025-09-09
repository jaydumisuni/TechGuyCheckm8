param(
  [string]$Version = "1.0.0"
)
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Join-Path $root ".."
cd $repo
python scripts\make_checksums.py
$zipName = "TechGuyCheckm8-v$Version.zip"
if (Test-Path $zipName) { Remove-Item $zipName -Force }
Compress-Archive -Path * -DestinationPath $zipName -Force -CompressionLevel Optimal
Write-Host "Packed $zipName"
