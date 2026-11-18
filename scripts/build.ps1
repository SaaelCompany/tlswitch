$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
go build -o tlswitch.exe .\cmd\tlswitch
Write-Host "собрано: tlswitch.exe"
