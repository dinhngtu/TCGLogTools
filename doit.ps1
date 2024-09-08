[CmdletBinding()]
param (
    [Parameter()]
    [switch]$Gather,
    [Parameter()]
    [switch]$Linear,
    [Parameter()]
    $LogPath,
    [Parameter()]
    $OutFile = "TCGlog.json"
)

$ErrorActionPreference = "Break"

import-Module "$PSScriptRoot\TCGLogTools.psd1" -Force
if ($LogPath) {
    $LogBytes = [IO.File]::ReadAllBytes($LogPath)
} else {
    $LogBytes = Get-TCGLogContent -LogType SRTMCurrent
}
ConvertTo-TCGEventLog -LogBytes $LogBytes -MinimizedX509CertInfo -GatherSBCP:$Gather -GatherDevice:$Gather -Linear:$Linear | ConvertTo-Json -Depth 99 | Out-File $OutFile
