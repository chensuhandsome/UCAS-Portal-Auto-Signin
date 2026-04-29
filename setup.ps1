param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json')
)

$ErrorActionPreference = 'Stop'

$examplePath = Join-Path $PSScriptRoot 'config.example.json'
if (-not (Test-Path -LiteralPath $examplePath)) {
    throw "Missing config.example.json in $PSScriptRoot"
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    Copy-Item -LiteralPath $examplePath -Destination $ConfigPath
    Write-Host "Created config.json from config.example.json"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

function Get-ConfigValue {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Default
    )
    if ($Object.PSObject.Properties[$Name]) {
        return $Object.$Name
    }
    return $Default
}

function Resolve-ConfigPath {
    param(
        [string]$Path,
        [string]$BasePath
    )
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return (Join-Path $BasePath $Path)
}

$credentialFile = Get-ConfigValue -Object $config -Name 'CredentialFile' -Default '.\credential.xml'
$credentialPath = Resolve-ConfigPath -Path $credentialFile -BasePath $PSScriptRoot

$username = Read-Host 'Campus username'
$password = Read-Host 'Campus password' -AsSecureString
$credential = New-Object System.Management.Automation.PSCredential($username, $password)

$credentialDir = Split-Path -Parent $credentialPath
if ($credentialDir -and -not (Test-Path -LiteralPath $credentialDir)) {
    New-Item -ItemType Directory -Path $credentialDir | Out-Null
}

$credential | Export-Clixml -LiteralPath $credentialPath
Write-Host "Saved encrypted credential to $credentialPath"
if ($env:OS -eq 'Windows_NT' -or $PSVersionTable.Platform -eq 'Win32NT') {
    Write-Host 'This file can be read only by the same Windows user account on this computer.'
} else {
    Write-Warning 'On non-Windows PowerShell, Export-Clixml does not use Windows DPAPI. Protect this folder carefully.'
}
Write-Host 'Run .\check-now.ps1 for a one-time check, or .\run-autologin.ps1 to keep monitoring.'
