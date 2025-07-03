$exe     = Join-Path $PSScriptRoot "target\release\CloudInitWin.exe"
$zip     = Join-Path $PSScriptRoot "CloudInitWin.zip"
$scripts = Join-Path $PSScriptRoot "scripts"

if (Test-Path $zip) {
    Remove-Item $zip -Force
}

Compress-Archive -LiteralPath $exe -DestinationPath $zip
Compress-Archive -LiteralPath "$scripts\install.ps1" -DestinationPath $zip -Update
Compress-Archive -LiteralPath "$scripts\uninstall.ps1" -DestinationPath $zip -Update
Compress-Archive -LiteralPath "$scripts\sysprep.ps1" -DestinationPath $zip -Update
Compress-Archive -LiteralPath "$scripts\Unattend.xml" -DestinationPath $zip -Update