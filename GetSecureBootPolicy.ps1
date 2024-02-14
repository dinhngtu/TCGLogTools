function Get-SecureBootPolicy {
    <#
.SYNOPSIS

Parses a Secure Boot policy.

.DESCRIPTION

Get-SecureBootPolicy parses either the default, system Secure Boot policy or a policy passed as a byte array. The byte array must be a raw, unsigned policy.

To my knowledge, the retrieval of the system Secure Boot policy is only possible in Win 10.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.EXAMPLE

Get-SecureBootPolicy

Description
-----------
Parses the system default Secure Boot policy.

.EXAMPLE

$UnsignedPolicyBytes = [IO.File]::ReadAllBytes('C:\Foo\Microsoft-Windows-Kits-Secure-Boot-Policy_Unsigned.p7b')
Get-SecureBootPolicy -PolicyBytes $UnsignedPolicyBytes

.OUTPUTS

SecureBoot.PolicyInformation

Outputs an object representing a parsed Secure Boot policy.

.NOTES

The binary format parsing (excluding the BCD object/element parsing) was derived from https://gist.github.com/Wack0/d657e5ca7296243c3af7576fe4f1a422

Also, this parser would not be complete to the extent it is without the invaluable Secure Boot policy information from Geoff Chappell: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/secureboot_policy_full.htm

This parser is not designed to incorporate robust bounds checking. If I had more than two unique secure boot policies to test against, I might consider adding more robust parsing logic.

Registry rule parsing is also not incorporated as I have yet to encounter a Secure Boot policy that has this information included.

PLEASE SEND ME YOUR SECURE BOOT POLICIES! I've only encountered three unique policies thus far. They are hard to come by, it seems.
#>

    [CmdletBinding()]
    param (
        [Parameter()]
        [Byte[]]
        $PolicyBytes
    )

    # Values obtained from https://gist.github.com/Wack0/d657e5ca7296243c3af7576fe4f1a422
    Add-Type -ErrorAction Stop -TypeDefinition @'
    namespace CodeIntegrity {
        [System.FlagsAttribute()]
        public enum SIPolicyRules {
            AllowedPrereleaseSigners =                        0x00000001,
            AllowedKitsSigners =                              0x00000002,
            EnabledUMCI =                                     0x00000004,
            EnabledBootMenuProtection =                       0x00000008,
            AllowedUMCIDebugOptions =                         0x00000010,
            EnabledUMCICacheDataVolumes =                     0x00000020,
            AllowedSeQuerySigningPolicyExtension =            0x00000040,
            RequiredWHQL =                                    0x00000080,
            EnabledFilterEditedBootOptions =                  0x00000100,
            DisabledUMCIUSN0Protection =                      0x00000200,
            DisabledWinloadDebuggingModeMenu =                0x00000400,
            EnabledStrongCryptoForCodeIntegrity =             0x00000800,
            AllowedNonMicrosoftUEFIApplicationsForBitLocker = 0x00001000,
            EnabledAlwaysUsePolicy =                          0x00002000,
            EnabledUMCITrustUSN0 =                            0x00004000,
            DisabledUMCIDebugOptionsTCBLowering =             0x00008000,
            EnabledAuditMode =                                0x00010000,
            DisabledFlightSigning =                           0x00020000,
            EnabledInheritDefaultPolicy =                     0x00040000,
            EnabledUnsignedSystemIntegrityPolicy =            0x00080000,
            AllowedDebugPolicyAugmented =                     0x00100000,
            RequiredEVSigners =                               0x00200000,
            EnabledBootAuditOnFailure =                       0x00400000,
            EnabledAdvancedBootOptionsMenu =                  0x00800000,
            DisabledScriptEnforcement =                       0x01000000,
            RequiredEnforceStoreApplications =                0x02000000,
            EnabledSecureSettingPolicy =                      0x04000000
        }
    }
'@

    $ObjectTypes = @{
        1 = 'Application'
        2 = 'Inherit'
        3 = 'Device'
    }

    $ImageTypes = @{
        1 = 'Firmware'
        2 = 'WindowsBootApp'
        3 = 'LegacyLoader'
        4 = 'RealMode'
    }

    $InheritableTypes = @{
        1 = 'InheritableByAnyObject'
        2 = 'InheritableByApplicationObject'
        3 = 'InheritableByDeviceObject'
    }

    $ElementClassTypes = @{
        1 = 'Library'
        2 = 'Application'
        3 = 'Device'
        4 = 'Template'
        5 = 'OEM'
    }

    $FormatTypes = @{
        1 = 'Device'
        2 = 'String'
        3 = 'Object'
        4 = 'ObjectList'
        5 = 'Integer'
        6 = 'Boolean'
        7 = 'IntegerList'
    }

    # reactos/boot/environ/include/bcd.h
    $ApplicationTypes = @{
        1 = 'FWBootMgr'
        2 = 'BootMgr'
        3 = 'OSLoader'
        4 = 'Resume'
        5 = 'MemDiag'
        6 = 'NTLdr'
        7 = 'SetupLdr'
        8 = 'Bootsector'
        9 = 'StartupCom'
    }

    $LibraryElementTypes = @{
        0x11000001 = 'Device'
        0x12000002 = 'Path'
        0x12000004 = 'Description'
        0x12000005 = 'Locale'
        0x14000006 = 'Inherit'
        0x15000007 = 'TruncateMemory'
        0x14000008 = 'RecoverySequence'
        0x16000009 = 'RecoveryEnabled'
        0x1700000A = 'BadMemoryList'
        0x1600000B = 'BadMemoryAccess'
        0x1500000C = 'FirstMegabytePolicy'
        0x1500000D = 'RelocatePhysical'
        0x1500000E = 'AvoidLowMemory'
        0x1600000F = 'TraditionalKseg'
        0x16000010 = 'BootDebug'
        0x15000011 = 'DebugType'
        0x15000012 = 'DebugAddress'
        0x15000013 = 'DebugPort'
        0x15000014 = 'BaudRate'
        0x15000015 = 'Channel'
        0x12000016 = 'TargetName'
        0x16000017 = 'NoUMEx'
        0x15000018 = 'DebugStart'
        0x12000019 = 'BusParams'
        0x1500001A = 'HostIP'
        0x1500001B = 'Port'
        0x1600001C = 'Dhcp'
        0x1200001D = 'Key'
        0x1600001E = 'VM'
        0x16000020 = 'BootEms'
        0x15000022 = 'EmsPort'
        0x15000023 = 'EmsBaudRate'
        0x12000030 = 'LoadOptions'
        0x16000040 = 'AdvancedOptions'
        0x16000041 = 'OptionsEdit'
        0x11000043 = 'BsdLogDevice'
        0x12000044 = 'BsdLogPath'
        0x16000046 = 'GraphicsModeDisabled'
        0x15000047 = 'ConfigAccessPolicy'
        0x16000048 = 'NoIntegrityChecks'
        0x16000049 = 'TestSigning'
        0x1200004A = 'FontPath'
        0x1500004B = 'IntegrityServices'
        0x1500004C = 'VolumeBandId'
        0x16000050 = 'ExtendedInput'
        0x15000051 = 'InitialConsoleInput'
        0x15000052 = 'GraphicsResolution'
        0x16000053 = 'RestartOnFailure'
        0x16000054 = 'HighestMode'
        0x16000060 = 'IsolatedContext'
        0x15000065 = 'DisplayMessage'
        0x15000066 = 'DisplayMessageOverride'
        0x16000067 = 'BootUxLogoDisable'
        0x16000068 = 'NoBootUxText'
        0x16000069 = 'NoBootUxProgress'
        0x1600006A = 'NoBootUxFade'
        0x1600006B = 'BootUxReservePoolDebug'
        0x1600006C = 'BootUxDisabled'
        0x1500006D = 'BootUxFadeFrames'
        0x1600006E = 'BootUxDumpStats'
        0x1600006F = 'BootUxShowStats'
        0x16000071 = 'MultiBootSystem'
        0x16000072 = 'NoKeyboard'
        0x15000073 = 'AliasWindowsKey'
        0x16000074 = 'BootShutdownDisabled'
        0x15000075 = 'PerformanceFrequency'
        0x15000076 = 'SecurebootRawPolicy'
        0x17000077 = 'AllowedInMemorySettings'
        0x15000079 = 'BootUxTransitionTime'
        0x1600007A = 'MobileGraphics'
        0x1600007B = 'ForceFipsCrypto'
        0x1500007D = 'BootErrorUx'
        0x1600007E = 'FlightSigning'
        0x1500007F = 'MeasuredBootLogFormat'
        0x15000080 = 'DisplayRotation'
        0x15000081 = 'LogControl'
        0x16000082 = 'NoFirmwareSync'
    }

    $OSLoaderElementTypes = @{
        0x21000001 = 'OSDevice'
        0x22000002 = 'SystemRoot'
        0x23000003 = 'ResumeObject'
        0x26000004 = 'StampDisks'
        0x26000010 = 'DetectHal'
        0x22000011 = 'Kernel'
        0x22000012 = 'Hal'
        0x22000013 = 'DbgTransport'
        0x25000020 = 'NX'
        0x25000021 = 'PAE'
        0x26000022 = 'WinPEMode'
        0x26000024 = 'NoCrashAutoReboot'
        0x26000025 = 'LastKnownGood'
        0x26000026 = 'OSLNoIntegrityChecks'
        0x26000027 = 'OSLTestSigning'
        0x26000030 = 'NoLowMem'
        0x25000031 = 'RemoveMemory'
        0x25000032 = 'IncreaseUserVa'
        0x25000033 = 'PerfMem'
        0x26000040 = 'Vga'
        0x26000041 = 'QuietBoot'
        0x26000042 = 'NoVesa'
        0x26000043 = 'NoVga'
        0x25000050 = 'ClusterModeAddressing'
        0x26000051 = 'UsePhysicalDestination'
        0x25000052 = 'RestrictApicCluster'
        0x22000053 = 'EVStore'
        0x26000054 = 'UseLegacyApicMode'
        0x25000055 = 'X2ApicPolicy'
        0x26000060 = 'OneCPU'
        0x25000061 = 'NumProc'
        0x26000062 = 'MaxProc'
        0x25000063 = 'ConfigFlags'
        0x26000064 = 'MaxGroup'
        0x26000065 = 'GroupAware'
        0x25000066 = 'GroupSize'
        0x26000070 = 'UseFirmwarePciSettings'
        0x25000071 = 'Msi'
        0x25000072 = 'PCIExpress'
        0x25000080 = 'SafeBoot'
        0x26000081 = 'SafeBootAlternateShell'
        0x26000090 = 'BootLog'
        0x26000091 = 'SOS'
        0x260000a0 = 'Debug'
        0x260000a1 = 'HalBreakpoint'
        0x260000A2 = 'UsePlatformClock'
        0x260000A3 = 'ForceLegacyPlatform'
        0x260000A4 = 'UsePlatformTick'
        0x260000A5 = 'DisableDynamicTick'
        0x250000A6 = 'TscSyncPolicy'
        0x260000b0 = 'Ems'
        0x250000C0 = 'ForceFailure'
        0x250000c1 = 'DriverLoadFailurePolicy'
        0x250000C2 = 'BootMenuPolicy'
        0x260000C3 = 'OneTimeAdvancedOptions'
        0x260000C4 = 'OneTimeOptionsEdit'
        0x250000E0 = 'BootStatusPolicy'
        0x260000E1 = 'DisableElamDrivers'
        0x250000F0 = 'HypervisorLaunchType'
        0x220000F1 = 'HypervisorPath'
        0x260000F2 = 'HypervisorDebug'
        0x250000F3 = 'HypervisorDebugType'
        0x250000F4 = 'HypervisorDebugPortNumber'
        0x250000F5 = 'HypervisorBaudrate'
        0x250000F6 = 'HypervisorChannel'
        0x250000F7 = 'BootUx'
        0x260000F8 = 'HypervisorDisableSLAT'
        0x220000F9 = 'HypervisorBusParams'
        0x250000FA = 'HypervisorNumProc'
        0x250000FB = 'HypervisorRootProcPerNode'
        0x260000FC = 'HypervisorUseLargeVTlb'
        0x250000FD = 'HypervisorHostIp'
        0x250000FE = 'HypervisorHostPort'
        0x250000FF = 'HypervisorDebuggerPages'
        0x25000100 = 'TpmBootEntropy'
        0x22000110 = 'HypervisorUseKey'
        0x22000112 = 'HypervisorProductSkuType'
        0x25000113 = 'HypervisorRootProc'
        0x26000114 = 'HypervisorDhcp'
        0x25000115 = 'HypervisorIommuPolicy'
        0x26000116 = 'HypervisoruseVAPic'
        0x22000117 = 'HypervisorLoadOptions'
        0x25000118 = 'HypervisorMSRFilterPolicy'
        0x25000119 = 'HypervisorMMIONXPolicy'
        0x25000120 = 'XSavePolicy'
        0x25000121 = 'XSaveAddFeature0'
        0x25000122 = 'XSaveAddFeature1'
        0x25000123 = 'XSaveAddFeature2'
        0x25000124 = 'XSaveAddFeature3'
        0x25000125 = 'XSaveAddFeature4'
        0x25000126 = 'XSaveAddFeature5'
        0x25000127 = 'XSaveAddFeature6'
        0x25000128 = 'XSaveAddFeature7'
        0x25000129 = 'XSaveRemoveFeature'
        0x2500012A = 'XSaveProcessorsMask'
        0x2500012b = 'XSaveDisable'
        0x2500012C = 'KernelDebugType'
        0x2200012D = 'KernelBusParams'
        0x2500012E = 'KernelDebugAddress'
        0x2500012F = 'KernelDebugPort'
        0x25000130 = 'ClaimedTPMCounter'
        0x25000131 = 'KernelChannel'
        0x22000132 = 'KernelTargetName'
        0x25000133 = 'KernelHostIP'
        0x25000134 = 'KernelPort'
        0x26000135 = 'KernelDHCP'
        0x22000136 = 'KernelKey'
        0x22000137 = 'IMCHiveName'
        0x21000138 = 'IMCDevice'
        0x25000139 = 'KernelBaudRate'
        0x22000140 = 'MfgMode'
        0x26000141 = 'Event'
        0x25000142 = 'VsmLaunchType'
        0x25000144 = 'HypervisorEnforcedCodeIntegrity'
        0x21000150 = 'SystemDataDevice'
    }

    $ResumeElementTypes = @{
        0x21000001 = 'FileDevice'
        0x22000002 = 'FilePath'
        0x26000003 = 'CustomSettings'
        0x26000004 = 'PAE'
        0x21000005 = 'AssociatedOsDevice'
        0x26000006 = 'DebugOptionEnabled'
        0x25000007 = 'BootUx'
        0x25000008 = 'BootMenuPolicy'
        0x26000024 = 'HormEnabled'
    }

    $LegacyLoaderElementTypes = @{
        0x22000001 = 'BPBString'
    }

    function Get-SystemSecureBootPolicyInformation {
        <#
    .SYNOPSIS

    Obtains the system Secure Boot policy blob.

    .DESCRIPTION

    Get-SystemSecureBootPolicyInformation obtains Secure Boot policy information including the raw bytes of the policy.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause

    .EXAMPLE

    Get-SystemSecureBootPolicyInformation

    .OUTPUTS

    SecureBoot.PolicyInformation

    An object representing a parsed SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION and the Secure Boot policy bytes.
    #>

        [CmdletBinding()]
        param ()

        # Helper function to interpret NTSTATUS codes as human-readable exceptions
        function Get-NTStatusException {
            param (
                [Parameter(Position = 0, Mandatory = $True)]
                [Int32]
                $ErrorCode
            )

            $Win32Native = [Int].Assembly.GetType('Microsoft.Win32.Win32Native')
            $LsaNtStatusToWinError = $Win32Native.GetMethod('LsaNtStatusToWinError', [Reflection.BindingFlags] 'NonPublic, Static')
            $GetMessage = $Win32Native.GetMethod('GetMessage', [Reflection.BindingFlags] 'NonPublic, Static')

            $WinErrorCode = $LsaNtStatusToWinError.Invoke($null, @($ErrorCode))

            $GetMessage.Invoke($null, @($WinErrorCode)).TrimEnd("`r`n")
        }

        Add-Type -ErrorAction Stop -TypeDefinition @'
        using System;
        using System.Runtime.InteropServices;

        namespace SecureBoot {
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
	        public struct SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
	        {
		        public Guid PolicyPublisher;
		        public uint PolicyVersion;
		        public uint PolicyOptions;
                public uint PolicySize;
	        }

            public class NativeMethods {
                [DllImport("ntdll.dll")]
		        public static extern int NtQuerySystemInformation(uint SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);
            }
        }
'@

        $ReturnedSize = [UInt32]::MinValue

        # dt uxtheme!_SYSTEM_INFORMATION_CLASS
        [UInt32] $SystemSecureBootPolicyFullInformation = 0xAB

        $Result = [SecureBoot.NativeMethods]::NtQuerySystemInformation(
            $SystemSecureBootPolicyFullInformation,
            [IntPtr]::Zero,
            [UInt32]::MinValue,
            [Ref] $ReturnedSize)

        $InsufficientBuffer = 0xC0000004

        # A 0xC0000004 NTSTATUS is expected where the size of the buffer to be allocated will be returned.
        if ($Result -ne $InsufficientBuffer) {
            throw (Get-NTStatusException -ErrorCode $Result)
            return
        }

        # Allocate the required size for the SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION structure.
        $PtrPolicy = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ReturnedSize)

        $BufferSize = $ReturnedSize
        $ReturnedSize = [UInt32]::MinValue

        $Result = [SecureBoot.NativeMethods]::NtQuerySystemInformation(
            $SystemSecureBootPolicyFullInformation,
            $PtrPolicy,
            [UInt32] $BufferSize,
            [Ref] $ReturnedSize)

        # An unexpected error occurred.
        if ($Result) {
            throw (Get-NTStatusException -ErrorCode $Result)
            # Free the unmanaged memory
            [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrPolicy)

            return
        }

        $PolicyInformation = [Runtime.InteropServices.Marshal]::PtrToStructure($PtrPolicy, [Type][SecureBoot.SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION])
        $PolicyInfoStructSize = [Runtime.InteropServices.Marshal]::SizeOf([Type][SecureBoot.SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION])

        $PolicyBytes = New-Object -TypeName Byte[]($PolicyInformation.PolicySize)

        [Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($PtrPolicy, $PolicyInfoStructSize), $PolicyBytes, 0, $PolicyInformation.PolicySize)

        [Runtime.InteropServices.Marshal]::FreeHGlobal($PtrPolicy)

        [PSCustomObject] @{
            PSTypeName      = 'SecureBoot.PolicyInformation'
            PolicyPublisher = $PolicyInformation.PolicyPublisher
            PolicyVersion   = $PolicyInformation.PolicyVersion
            PolicyOptions   = $PolicyInformation.PolicyOptions
            PolicySize      = $PolicyInformation.PolicySize
            PolicyBytes     = $PolicyBytes
        }
    }

    $SecureBootPolicyBytes = $null

    if ($PolicyBytes) {
        $SecureBootPolicyBytes = $PolicyBytes
    }
    else {
        # If -PolicyBytes was not specified, obtain the system default Secure Boot policy.
        $PolicyInfo = Get-SystemSecureBootPolicyInformation -ErrorAction Stop
        $SecureBootPolicyBytes = $PolicyInfo.PolicyBytes
    }

    try {
        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(, $SecureBootPolicyBytes)
        $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream, ([Text.Encoding]::Unicode)
    }
    catch {
        throw $_
        return
    }

    $FormatVersion = $BinaryReader.ReadUInt16()
    $PolicyVersion = $BinaryReader.ReadUInt32()
    $PolicyPublisher = [Guid] $BinaryReader.ReadBytes(16)
    $CanUpdateCount = $BinaryReader.ReadUInt16()
    $CanUpdateGuids = $null

    # I assume this has to do with the signers who are permitted
    # to update secure boot policy.
    if ($CanUpdateCount) {
        $CanUpdateGuids = New-Object -TypeName Guid[]($CanUpdateCount)
    }

    for ($i = 0; $i -lt $CanUpdateCount; $i++) {
        $CanUpdateGuids[$i] = [Guid] $BinaryReader.ReadBytes(16)
    }

    $SIPolicyValue = $BinaryReader.ReadUInt32()
    $SIPolicyOptions = $null

    # Obtain the system integrity (SI) options. These are equivalent to Device Guard
    # code integrity rule options.
    if ($SIPolicyValue) { $SIPolicyOptions = [CodeIntegrity.SIPolicyRules] $SIPolicyValue }

    $BcdRulesCount = $BinaryReader.ReadUInt16()

    # To do: Registry rules will not be parsed now as I don't have
    # an example secure boot policy that contains registry rules.
    $RegistryRulesCount = $BinaryReader.ReadUInt16()

    if ($RegistryRulesCount) {
        Write-Warning "If you're seeing this warning, your Secure Boot policy has registry rules present. Registry rules are not currently parsed as I have yet to encounter a policy that had them. Please let @mattifestation know and ideally supply your secure boot policy."
    }

    $SecureBootPolicy = [PSCustomObject] @{
        PSTypeName      = 'SecureBoot.Policy'
        FormatVersion   = $FormatVersion
        PolicyVersion   = $PolicyVersion
        PolicyPublisher = $PolicyPublisher
        CanUpdate       = $CanUpdateGuids
        SIPolicyOptions = $SIPolicyOptions
        BCDRules        = $null
        PolicyBytes     = $SecureBootPolicyBytes
        PolicyHash      = $null
    }

    $HashStream = $null
    try {
        $HashStream = [System.IO.MemoryStream]::new($SecureBootPolicyBytes)
        $SecureBootPolicy.PolicyHash = (Get-FileHash -Algorithm SHA256 -InputStream $HashStream).Hash
    }
    finally {
        if ($null -ne $HashStream) {
            $HashStream.Close()
        }
    }

    $RawBCDRules = New-Object -TypeName PSObject[]($BcdRulesCount)

    # Parse the BCD objects aside from the BCD element values.
    # Those will need to be captured in the second pass.
    for ($i = 0; $i -lt ([Int] $BcdRulesCount); $i++) {
        $ObjectTypeVal = $BinaryReader.ReadInt32()
        $ElementTypeVal = $BinaryReader.ReadInt32()
        $ValueOffset = $BinaryReader.ReadUInt32()

        $ObjectType = $ObjectTypes[(($ObjectTypeVal -band 0xF0000000) -shr 28)]

        $ImageCodeVal = ($ObjectTypeVal -band 0x00F00000) -shr 20

        $ObjectSubType = $null

        switch ($ObjectType) {
            'Application' { $ObjectSubType = $ImageTypes[$ImageCodeVal] }
            'Inherit' { $ObjectSubType = $InheritableTypes[$ImageCodeVal] }
        }

        $ElementType = $ElementClassTypes[(($ElementTypeVal -band 0xF0000000) -shr 28)]
        # Get the datatype of the element value
        $ElementFormat = $FormatTypes[(($ElementTypeVal -band 0x0F000000) -shr 24)]

        $ApplicationType = $null

        if ($ObjectType -eq 'Application') {
            $ApplicationType = $ApplicationTypes[($ObjectTypeVal -band 0x000FFFFF)]
        }

        $ElementName = $null

        # To add: BOOTMGR, DEVICE, MEMTEST. These are unlikely though.
        if ($ElementType -eq 'Library') {
            $ElementName = $LibraryElementTypes[$ElementTypeVal]
        }
        elseif ($ApplicationType -eq 'OSLoader') {
            $ElementName = $OSLoaderElementTypes[$ElementTypeVal]
        }
        elseif ($ApplicationType -eq 'Resume') {
            $ElementName = $ResumeElementTypes[$ElementTypeVal]
        }
        elseif ($ApplicationType -eq 'NTLdr') {
            $ElementName = $LegacyLoaderElementTypes[$ElementTypeVal]
        }
        elseif ($ElementName -eq $null) {
            # Fallback in case there isn't element name coverage
            # This mirrors how bcdedit.exe handles this case.
            $ElementName = "Custom:$($ElementTypeVal.ToString('X8'))"
        }

        $RawBCDRules[$i] = [PSCustomObject] @{
            PSTypeName                = 'SecureBoot.BCDRule'
            ObjectType                = $ObjectSubType
            ObjectName                = $ApplicationType
            ObjectTypeRawValue        = "0x$($ObjectTypeVal.ToString('X8'))"
            ElementName               = $ElementName
            ElementTypeRawValue       = "0x$($ElementTypeVal.ToString('X8'))"
            ElementPolicyType         = $null
            ElementPolicyValue        = $null
            ElementPolicyDefaultValue = $null
            ElementSubjectToBitlocker = $False
            ElementSubjectToVBS       = $False
        }
    }

    $CurrentPosition = $BinaryReader.BaseStream.Position

    Write-Verbose "Element policy value table offset: 0x$($CurrentPosition.ToString('X8'))"

    # Second pass to retrieve BCD element policies from their respective offsets.
    # This portion would not have been possible without the help of Geoff Chappell's article:
    #  www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/secureboot_policy_full.htm
    for ($i = 0; $i -lt $BcdRulesCount; $i++) {
        $ValueTypeVal = $BinaryReader.ReadUInt16()
        $ValType = ([Byte] ($ValueTypeVal -band 0x1F)).ToString()
        $ValApplicability = [Byte] ($ValueTypeVal -band 0xE0)

        $SubjectToBitlocker = $False
        $SubjectToVBS = $False

        if ($ValApplicability -band 0x20) { $SubjectToBitlocker = $True }
        if ($ValApplicability -band 0x40) { $SubjectToVBS = $True }

        $ValueType = $null
        $DefaultValue = $null
        $Value = $null

        # Consider resolving values for well-known elements -
        # e.g. NX values would map to human-readable values.
        # Until then, refer to Geoff Chappell's "BCD Elements" reference.
        switch ($ValType) {
            '0' {
                # FYI, I have not personally encountered this type yet (i.e. I make no guarantees that I am parsing this correctly). I need more secure boot policies to parse!
                $ValueType = 'String'
                $StringSizeInBytes = $BinaryReader.ReadUInt16()
                $ValueBytes = $BinaryReader.ReadBytes($StringSizeInBytes)
                $Value = [Text.Encoding]::Unicode.GetString($ValueBytes)
            }

            '1' {
                $ValueType = 'Boolean'
                # $DefaultValue is not applicable here
                $Value = [Bool] $BinaryReader.ReadUInt16()
            }

            '2' {
                # FYI, I have not personally encountered this type yet (i.e. I make no guarantees that I am parsing this correctly). I need more secure boot policies to parse!
                $ValueType = 'UInt32'
                $DefaultValue = $BinaryReader.ReadUInt32()
            }

            '3' {
                # FYI, I have not personally encountered this type yet (i.e. I make no guarantees that I am parsing this correctly). I need more secure boot policies to parse!
                $ValueType = 'UInt32AcceptableRange'
                $DefaultValue = $BinaryReader.ReadUInt32()
                $Value = New-Object -TypeName UInt32[](2)
                $Value[0] = $BinaryReader.ReadUInt32() # Lowest acceptable value
                $Value[1] = $BinaryReader.ReadUInt32() # Highest acceptable value
            }

            '4' {
                # FYI, I have not personally encountered this type yet (i.e. I make no guarantees that I am parsing this correctly). I need more secure boot policies to parse!
                $ValueType = 'UInt32Array'
                $DefaultValue = $BinaryReader.ReadUInt32()
                $ULongArraySize = $BinaryReader.ReadUInt16()
                $Value = New-Object -TypeName UInt32[]($ULongArraySize)

                for ($j = 0; $j -lt $ULongArraySize; $j++) {
                    $Value[$j] = $BinaryReader.ReadUInt32()
                }
            }

            '5' {
                $ValueType = 'UInt64Array'
                $DefaultValue = $BinaryReader.ReadUInt64()
            }

            '6' {
                # FYI, I have not personally encountered this type yet (i.e. I make no guarantees that I am parsing this correctly). I need more secure boot policies to parse!
                $ValueType = 'UInt64AcceptableRange'
                $DefaultValue = $BinaryReader.ReadUInt64()
                $Value = New-Object -TypeName UInt64[](2)
                $Value[0] = $BinaryReader.ReadUInt64() # Lowest acceptable value
                $Value[1] = $BinaryReader.ReadUInt64() # Highest acceptable value
            }

            '7' {
                # FYI, I have not personally encountered this type yet (i.e. I make no guarantees that I am parsing this correctly). I need more secure boot policies to parse!
                $ValueType = 'UInt64Array'
                $DefaultValue = $BinaryReader.ReadUInt64()
                $ULongArraySize = $BinaryReader.ReadUInt16()
                $Value = New-Object -TypeName UInt64[]($ULongArraySize)

                for ($j = 0; $j -lt $ULongArraySize; $j++) {
                    $Value[$j] = $BinaryReader.ReadUInt64()
                }
            }

            '8' {
                $ValueType = 'ValuePermission'
                # $DefaultValue is not applicable here
                $RawValue = $BinaryReader.ReadUInt16()

                $Value = $null

                if ($RawValue -eq 0) {
                    $Value = 'CreationNotPermitted'
                }
                else {
                    $Value = 'SetAndDeleteNotPermitted'
                }
            }

            '9' {
                # It's not clear on how this data should be properly interpreted based on Geoff's description:
                # https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/secureboot_policy_full.htm
                Write-Warning "Element table entry (type 9) encountered! It is currently unclear as to how this data should be parsed. If you're seeing this warning, please let @mattifestation know and ideally supply your secure boot policy!"
            }

            '10' {
                # FYI, I have not personally encountered this type yet (i.e. I make no guarantees that I am parsing this correctly). I need more secure boot policies to parse!
                $ValueType = 'ByteArray'
                $StringSizeInBytes = $BinaryReader.ReadUInt16()
                $Value = $BinaryReader.ReadBytes($StringSizeInBytes)
            }
        }

        $RawBCDRules[$i].ElementPolicyType = $ValueType
        $RawBCDRules[$i].ElementPolicyValue = $Value
        $RawBCDRules[$i].ElementPolicyDefaultValue = $DefaultValue
        $RawBCDRules[$i].ElementSubjectToBitlocker = $SubjectToBitlocker
        $RawBCDRules[$i].ElementSubjectToVBS = $SubjectToVBS
    }

    $BinaryReader.Close()

    $SecureBootPolicy.BCDRules = $RawBCDRules

    $SecureBootPolicy
}
