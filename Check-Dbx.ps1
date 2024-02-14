[CmdletBinding()]
param (
    [Parameter(Position = 0)][string]$PatchFile = ".\content.bin"
)

Write-Host "Checking for Administrator permission..."
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Open the PowerShell console as administrator and run this script again."
    Break
}
else {
    Write-Host "Running as administrator � continuing execution..." -ForegroundColor Green
}

$patchfile = (Get-ChildItem $patchfile).FullName

Import-Module -Force .\Get-UEFIDatabaseSignatures.ps1

# Print computer info
$computer = gwmi Win32_ComputerSystem
$bios = gwmi Win32_BIOS
"Manufacturer: " + $computer.Manufacturer
"Model: " + $computer.Model
$biosinfo = $bios.Manufacturer , $bios.Name , $bios.SMBIOSBIOSVersion , $bios.Version -join ", "
"BIOS: " + $biosinfo + "`n"

$DbxRaw = Get-SecureBootUEFI dbx
$DbxFound = $DbxRaw | Get-UEFIDatabaseSignatures

$DbxBytesRequired = [IO.File]::ReadAllBytes($patchfile)
$DbxRequired = Get-UEFIDatabaseSignatures -BytesIn $DbxBytesRequired

# Flatten into an array of required EfiSignatureData data objects
$RequiredArray = foreach ($EfiSignatureList in $DbxRequired) {
    Write-Verbose $EfiSignatureList
    foreach ($RequiredSignatureData in $EfiSignatureList.SignatureList) {
        Write-Verbose  $RequiredSignatureData
        $RequiredSignatureData.SignatureData
    }
}
Write-Information "Required `n" $RequiredArray

# Flatten into an array of EfiSignatureData data objects (read from dbx)
$FoundArray = foreach ($EfiSignatureList in $DbxFound) {
    Write-Verbose $EfiSignatureList
    foreach ($FoundSignatureData in $EfiSignatureList.SignatureList) {
        Write-Verbose  $FoundSignatureData
        $FoundSignatureData.SignatureData
    }
}
Write-Information "Found `n" $FoundArray

$i = 0
$requiredCount = $RequiredArray.Count
foreach ($RequiredSig in $RequiredArray) {
    [PSCustomObject]@{
        RequiredSig = $RequiredSig;
        Applied     = $FoundArray -contains $RequiredSig;
    }
    $i += 1
    Write-Progress -Activity 'Checking if all patches applied' -Status "Checking element $i of $requiredCount" -PercentComplete ($i / $requiredCount * 100)
}
