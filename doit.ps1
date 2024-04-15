[CmdletBinding()]
param (
    [Parameter()]
    [switch]$Gather,
    [Parameter()]
    [switch]$Linear
)

import-Module .\TCGLogTools.psd1 -Force
ConvertTo-TCGEventLog -LogBytes (Get-TCGLogContent -LogType SRTMCurrent) -MinimizedX509CertInfo -GatherSBCP:$Gather -GatherDevice:$Gather -Linear:$Linear | ConvertTo-Json -Depth 99 | Out-File 'TCGlog.json'
