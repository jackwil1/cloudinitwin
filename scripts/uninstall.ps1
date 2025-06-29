$ErrorActionPreference = 'Stop'

$serviceName = "CloudInitWin"
$destDir = "$env:ProgramFiles\CloudInitWin"

# Check if running as Administrator
if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator."
    exit 1
}

# Stop and remove existing service
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping and removing service: $serviceName"
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName
}

# Remove the installed files
Write-Host "Removing installed files from $destDir"
Remove-Item -Path $destDir -Recurse -Force

Write-Host "Uninstall complete."
