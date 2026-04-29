param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.json')
)

$ErrorActionPreference = 'Stop'

& (Join-Path $PSScriptRoot 'auto-login.ps1') -ConfigPath $ConfigPath -Once
