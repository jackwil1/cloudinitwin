$ErrorActionPreference = 'Stop'

$exeName = "CloudInitWin.exe"
$serviceName = "CloudInitWin"
$sourceExe = Join-Path $PSScriptRoot "$exeName"
$destDir = "$env:ProgramFiles\CloudInitWin"
$destExe = Join-Path $destDir $exeName

# Check if running as Administrator
if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as an Administrator."
    exit 1
}

# Check if source executable exists
if (-Not (Test-Path -Path $sourceExe)) {
    Write-Error "Source executable not found at $sourceExe. Please build the project in release mode first."
    exit 1
}

Write-Host "Installer started."

# Create destination directory
if (-Not (Test-Path -Path $destDir)) {
    Write-Host "Creating destination directory: $destDir"
    New-Item -ItemType Directory -Path $destDir | Out-Null
}

# Copy executable
Write-Host "Copying executable to $destExe"
Copy-Item -Path $sourceExe -Destination $destExe -Force

# Stop and remove existing service
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping and removing existing service: $serviceName"
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $serviceName
    Start-Sleep -s 2 # Give time for service to be deleted
}

# Create the service
Write-Host "Creating service: $serviceName"
sc.exe create $serviceName binPath= "$destExe" start= auto obj= "LocalSystem" DisplayName= "CloudInitWin Service" depend= "NSI/ProfSvc/Winmgmt"
Write-Host "Setting service description"
sc.exe description $serviceName "Runs the CloudInitWin application."
Write-Host "Service '$serviceName' created successfully."

# Install OpenSSH
Write-Host "Installing OpenSSH"
Add-WindowsCapability -Online -Name OpenSSH.Server;
Start-Service sshd;
Set-Service -Name sshd -StartupType "Automatic"
$firewallParams = @{
    Name        = 'OpenSSH-Server-In-TCP'
    DisplayName = 'Inbound rule for OpenSSH Server on TCP port 22'
    Action      = 'Allow'
    Direction   = 'Inbound'
    Enabled     = 'True'
    Profile     = 'Any'
    Protocol    = 'TCP'
    LocalPort   = 22
}
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    New-NetFirewallRule @firewallParams
}
$shellParams = @{
    Path         = 'HKLM:\SOFTWARE\OpenSSH'
    Name         = 'DefaultShell'
    Value        = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    PropertyType = 'String'
    Force        = $true
}
New-ItemProperty @shellParams

Write-Host "Installation complete."
