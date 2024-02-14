#Requires -Version 7

# APIs required to interface with the TPM service
Add-Type -ErrorAction Stop -TypeDefinition @'
    using System;
    using System.Runtime.InteropServices;

    namespace TPMBaseServices {
        public enum TPM_VERSION {
            TPM_VERSION_UNKNOWN = 0,
            TPM_VERSION_12,
            TPM_VERSION_20
        }

        public enum TPM_IFTYPE : uint {
            TPM_IFTYPE_UNKNOWN = 0,
            TPM_IFTYPE_1,
            TPM_IFTYPE_TRUSTZONE,
            TPM_IFTYPE_HW,
            TPM_IFTYPE_EMULATOR,
            TPM_IFTYPE_SPB
        }

        public enum TBS_TCGLOG : uint {
            TBS_TCGLOG_SRTM_CURRENT = 0,
            TBS_TCGLOG_DRTM_CURRENT,
            TBS_TCGLOG_SRTM_BOOT,
            TBS_TCGLOG_SRTM_RESUME
        }

        public struct TPM_DEVICE_INFO {
            public uint structVersion;
            public TPM_VERSION tpmVersion;
            public TPM_IFTYPE tpmInterfaceType;
            public uint tpmImpRevision;
        }

        public class UnsafeNativeMethods {
            [DllImport("tbs.dll")]
            public static extern uint Tbsi_GetDeviceInfo(ulong Size, out TPM_DEVICE_INFO Info);

            // This API is much more flexible than Tbsi_Get_TCG_Log because you don't need to get a TBS context.
            [DllImport("tbs.dll")]
            public static extern uint Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG logType, IntPtr pOutputBuf, ref uint OutputBufLen);
        }
    }
'@

#region: enums required for multiple functions

# Used to display friendly error messages if a TBS function fails.
$Script:TBSReturnCodes = @{
    ([UInt32] 2150121473) = 'An internal software error occurred.'
    ([UInt32] 2150121474) = 'One or more parameter values are not valid.'
    ([UInt32] 2150121475) = 'A specified output pointer is bad.'
    ([UInt32] 2150121476) = 'The specified context handle does not refer to a valid context.'
    ([UInt32] 2150121477) = 'The specified output buffer is too small.'
    ([UInt32] 2150121478) = 'An error occurred while communicating with the TPM.'
    ([UInt32] 2150121479) = 'A context parameter that is not valid was passed when attempting to create a TBS context.'
    ([UInt32] 2150121480) = 'The TBS service is not running and could not be started.'
    ([UInt32] 2150121481) = 'A new context could not be created because there are too many open contexts.'
    ([UInt32] 2150121482) = 'A new virtual resource could not be created because there are too many open virtual resources.'
    ([UInt32] 2150121483) = 'The TBS service has been started but is not yet running.'
    ([UInt32] 2150121484) = 'The physical presence interface is not supported.'
    ([UInt32] 2150121485) = 'The command was canceled.'
    ([UInt32] 2150121486) = 'The input or output buffer is too large.'
    ([UInt32] 2150121487) = 'A compatible Trusted Platform Module (TPM) Security Device cannot be found on this computer.'
    ([UInt32] 2150121488) = 'The TBS service has been disabled.'
    ([UInt32] 2150121489) = 'The TBS event log is not available.'
    ([UInt32] 2150121490) = 'The caller does not have the appropriate rights to perform the requested operation.'
    ([UInt32] 2150121491) = 'The TPM provisioning action is not allowed by the specified flags.'
    ([UInt32] 2150121492) = 'The Physical Presence Interface of this firmware does not support the requested method.'
    ([UInt32] 2150121493) = 'The requested TPM OwnerAuth value was not found.'
    # 2150121493 may be a typo in the docs for the below return code. Need to reverse tbs.dll to confirm
    ([UInt32] 2150121494) = "The TPM provisioning did not complete. For more information on completing the provisioning, call the Win32_Tpm WMI method for provisioning the TPM ('Provision') and check the returned information."
}

# Obtained from wbcl.h in the WDK
# These refer to Windows-specific data types for PCR 12-14 and -1 (TrustPoint)
$Script:SIPAEventMapping = @{
    # SIPAEVENTTYPE_CONTAINER
    # All of these types will contain embedded event data
    0x40010001 = 'TrustBoundary'                   # SIPAEVENT_TRUSTBOUNDARY
    0x40010002 = 'ELAMAggregation'                 # SIPAEVENT_ELAM_AGGREGATION
    0x40010003 = 'LoadedModuleAggregation'         # SIPAEVENT_LOADEDMODULE_AGGREGATION
    0xC0010004 = 'TrustpointAggregation'           # SIPAEVENT_TRUSTPOINT_AGGREGATION
    0x40010005 = 'KSRAggregation'                  # SIPAEVENT_KSR_AGGREGATION
    0x40010006 = 'KSRSignedMeasurementAggregation' # SIPAEVENT_KSR_SIGNED_MEASUREMENT_AGGREGATION

    # SIPAEVENTTYPE_ERROR
    0x00030001 = 'ErrorFirmwareFailure'
    0x80030002 = 'ErrorTPMFailure'
    0x00030003 = 'ErrorInternalFailure'

    # SIPAEVENTTYPE_INFORMATION
    0x00020001 = 'Information'         # SIPAEVENT_INFORMATION
    0x00020002 = 'BootCounter'         # SIPAEVENT_BOOTCOUNTER
    0x00020003 = 'TransferControl'     # SIPAEVENT_TRANSFER_CONTROL
    0x00020004 = 'ApplicationReturn'   # SIPAEVENT_APPLICATION_RETURN
    0x00020005 = 'BitlockerUnlock'     # SIPAEVENT_BITLOCKER_UNLOCK
    0x00020006 = 'EventCounter'        # SIPAEVENT_EVENTCOUNTER
    0x00020007 = 'CounterID'           # SIPAEVENT_COUNTERID
    0x00020008 = 'MORBitNotCancelable' # SIPAEVENT_MORBIT_NOT_CANCELABLE
    0x00020009 = 'ApplicationSVN'      # SIPAEVENT_APPLICATION_SVN
    0x0002000A = 'SVNChainStatus'      # SIPAEVENT_SVN_CHAIN_STATUS
    0x0002000B = 'MORBitAPIStatus'     # SIPAEVENT_MORBIT_API_STATUS

    # SIPAEVENTTYPE_PREOSPARAMETER
    0x00040001 = 'BootDebugging'       # SIPAEVENT_BOOTDEBUGGING
    0x00040002 = 'BootRevocationList'  # SIPAEVENT_BOOT_REVOCATION_LIST

    # SIPAEVENTTYPE_OSPARAMETER
    0x00050001 = 'OSKernelDebug'             # SIPAEVENT_OSKERNELDEBUG
    0x00050002 = 'CodeIntegrity'             # SIPAEVENT_CODEINTEGRITY
    0x00050003 = 'TestSigning'               # SIPAEVENT_TESTSIGNING
    0x00050004 = 'DataExecutionPrevention'   # SIPAEVENT_DATAEXECUTIONPREVENTION
    0x00050005 = 'SafeMode'                  # SIPAEVENT_SAFEMODE
    0x00050006 = 'WinPE'                     # SIPAEVENT_WINPE
    0x00050007 = 'PhysicalAddressExtension'  # SIPAEVENT_PHYSICALADDRESSEXTENSION
    0x00050008 = 'OSDevice'                  # SIPAEVENT_OSDEVICE
    0x00050009 = 'SystemRoot'                # SIPAEVENT_SYSTEMROOT
    0x0005000A = 'HypervisorLaunchType'      # SIPAEVENT_HYPERVISOR_LAUNCH_TYPE
    0x0005000B = 'HypervisorPath'            # SIPAEVENT_HYPERVISOR_PATH
    0x0005000C = 'HypervisorIOMMUPolicy'     # SIPAEVENT_HYPERVISOR_IOMMU_POLICY
    0x0005000D = 'HypervisorDebug'           # SIPAEVENT_HYPERVISOR_DEBUG
    0x0005000E = 'DriverLoadPolicy'          # SIPAEVENT_DRIVER_LOAD_POLICY
    0x0005000F = 'SIPolicy'                  # SIPAEVENT_SI_POLICY
    0x00050010 = 'HypervisorMMIONXPolicy'    # SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY
    0x00050011 = 'HypervisorMSRFilterPolicy' # SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY
    0x00050012 = 'VSMLaunchType'             # SIPAEVENT_VSM_LAUNCH_TYPE
    0x00050013 = 'OSRevocationList'          # SIPAEVENT_OS_REVOCATION_LIST
    0x00050014 = 'SMTStatus'                 # SIPAEVENT_SMT_STATUS
    0x00050020 = 'VSMIDKInfo'                # SIPAEVENT_VSM_IDK_INFO
    0x00050021 = 'FlightSigning'             # SIPAEVENT_FLIGHTSIGNING
    0x00050022 = 'PagefileEncryptionEnabled' # SIPAEVENT_PAGEFILE_ENCRYPTION_ENABLED
    0x00050023 = 'VSMIDKSInfo'               # SIPAEVENT_VSM_IDKS_INFO
    0x00050024 = 'HibernationDisabled'       # SIPAEVENT_HIBERNATION_DISABLED
    0x00050025 = 'DumpsDisabled'             # SIPAEVENT_DUMPS_DISABLED
    0x00050026 = 'DumpEncryptionEnabled'     # SIPAEVENT_DUMP_ENCRYPTION_ENABLED
    0x00050027 = 'DumpEncryptionKeyDigest'   # SIPAEVENT_DUMP_ENCRYPTION_KEY_DIGEST
    0x00050028 = 'LSAISOConfig'              # SIPAEVENT_LSAISO_CONFIG
    0x00050029 = 'SBCPInfo'
    0x00050030 = 'HypervisorBootDMAProtection'

    # SIPAEVENTTYPE_AUTHORITY
    0x00060001 = 'NoAuthority'               # SIPAEVENT_NOAUTHORITY
    0x00060002 = 'AuthorityPubKey'           # SIPAEVENT_AUTHORITYPUBKEY

    # SIPAEVENTTYPE_LOADEDIMAGE
    0x00070001 = 'FilePath'                  # SIPAEVENT_FILEPATH
    0x00070002 = 'ImageSize'                 # SIPAEVENT_IMAGESIZE
    0x00070003 = 'HashAlgorithmID'           # SIPAEVENT_HASHALGORITHMID
    0x00070004 = 'AuthenticodeHash'          # SIPAEVENT_AUTHENTICODEHASH
    0x00070005 = 'AuthorityIssuer'           # SIPAEVENT_AUTHORITYISSUER
    0x00070006 = 'AuthoritySerial'           # SIPAEVENT_AUTHORITYSERIAL
    0x00070007 = 'ImageBase'                 # SIPAEVENT_IMAGEBASE
    0x00070008 = 'AuthorityPublisher'        # SIPAEVENT_AUTHORITYPUBLISHER
    0x00070009 = 'AuthoritySHA1Thumbprint'   # SIPAEVENT_AUTHORITYSHA1THUMBPRINT
    0x0007000A = 'ImageValidated'            # SIPAEVENT_IMAGEVALIDATED
    0x0007000B = 'ModuleSVN'                 # SIPAEVENT_MODULE_SVN

    # SIPAEVENTTYPE_TRUSTPOINT
    0x80080001 = 'Quote'                     # SIPAEVENT_QUOTE
    0x80080002 = 'QuoteSignature'            # SIPAEVENT_QUOTESIGNATURE
    0x80080003 = 'AIKID'                     # SIPAEVENT_AIKID
    0x80080004 = 'AIKPubDigest'              # SIPAEVENT_AIKPUBDIGEST

    # SIPAEVENTTYPE_ELAM
    0x00090001 = 'ELAMKeyname'               # SIPAEVENT_ELAM_KEYNAME
    0x00090002 = 'ELAMConfiguration'         # SIPAEVENT_ELAM_CONFIGURATION
    0x00090003 = 'ELAMPolicy'                # SIPAEVENT_ELAM_POLICY
    0x00090004 = 'ELAMMeasured'              # SIPAEVENT_ELAM_MEASURED

    # SIPAEVENTTYPE_VBS
    0x000A0001 = 'VBSVSMRequired'                # SIPAEVENT_VBS_VSM_REQUIRED
    0x000A0002 = 'VBSSecurebootRequired'         # SIPAEVENT_VBS_SECUREBOOT_REQUIRED
    0x000A0003 = 'VBSIOMMURequired'              # SIPAEVENT_VBS_IOMMU_REQUIRED
    0x000A0004 = 'VBSNXRequired'                 # SIPAEVENT_VBS_MMIO_NX_REQUIRED
    0x000A0005 = 'VBSMSRFilteringRequired'       # SIPAEVENT_VBS_MSR_FILTERING_REQUIRED
    0x000A0006 = 'VBSMandatoryEnforcement'       # SIPAEVENT_VBS_MANDATORY_ENFORCEMENT
    0x000A0007 = 'VBSHVCIPolicy'                 # SIPAEVENT_VBS_HVCI_POLICY
    0x000A0008 = 'VBSMicrosoftBootChainRequired' # SIPAEVENT_VBS_MICROSOFT_BOOT_CHAIN_REQUIRED
    0x000A0009 = 'VBSDumpUsesAMERoot'
    0x000A000A = 'VBSVSMNosecretsEnforced'

    # SIPAEVENTTYPE_KSR
    0x000B0001 = 'KSRSignature'                  # SIPAEVENT_KSR_SIGNATURE

    # SIPAEVENTTYPE_DRTM
    0x000C0001 = 'DRTMStateAuth'
    0x000C0002 = 'DRTMSMMLevel'
    0x000C0003 = 'DRTMAMDSMMHash'
    0x000C0004 = 'DRTMAMDSMMSignerKey'
}

$Script:SMTStatusTextMapping = @{
    [UInt32] 0 = "Disabled"
    [UInt32] 1 = "Enabled"
    [UInt32] 2 = "SoftwareDisabled"
}

$Script:TransferControlMapping = @{
    [UInt32] 0x00000000l = "NONE"
    [UInt32] 0x00000001l = "OSLOADER"
    [UInt32] 0x00000002l = "RESUME"
    [UInt32] 0x00000003l = "MSUTILITY"
    [UInt32] 0x00000004l = "NOSIGCHECK"
    [UInt32] 0x00000005l = "HYPERVISOR"
    [UInt32] 0xFFFFFFFFl = "Unknown"
}

$Script:DigestAlgorithmMapping = @{
    [UInt16] 0  = 'TPM_ALG_ERROR'
    [UInt16] 1  = 'TPM_ALG_RSA'
    [UInt16] 4  = 'TPM_ALG_SHA1'
    [UInt16] 5  = 'TPM_ALG_HMAC'
    [UInt16] 6  = 'TPM_ALG_AES'
    [UInt16] 7  = 'TPM_ALG_MGF1'
    [UInt16] 8  = 'TPM_ALG_KEYEDHASH'
    [UInt16] 10 = 'TPM_ALG_XOR'
    [UInt16] 11 = 'TPM_ALG_SHA256'
    [UInt16] 12 = 'TPM_ALG_SHA384'
    [UInt16] 13 = 'TPM_ALG_SHA512'
    [UInt16] 16 = 'TPM_ALG_NULL'
    [UInt16] 18 = 'TPM_ALG_SM3_256'
    [UInt16] 39 = 'TPM_ALG_SHA3_256'
    [UInt16] 40 = 'TPM_ALG_SHA3_384'
    [UInt16] 41 = 'TPM_ALG_SHA3_512'
}

$Script:HashAlgorithmMapping = @{
    0x00008001 = 'CALG_MD2'
    0x00008002 = 'CALG_MD4'
    0x00008003 = 'CALG_MD5'
    0x00008004 = 'CALG_SHA1'
    0x0000800C = 'CALG_SHA_256'
    0x0000800D = 'CALG_SHA_384'
    0x0000800E = 'CALG_SHA_512'
}

$Script:FvebUnlockFlagMapping = @{
    0x00000000 = 'NONE'
    0x00000001 = 'CACHED'
    0x00000002 = 'MEDIA'
    0x00000004 = 'TPM'
    0x00000010 = 'PIN'
    0x00000020 = 'EXTERNAL'
    0x00000040 = 'RECOVERY'
    0x00000080 = 'PASSPHRASE'
    0x00000100 = 'NBP'
    0x00000200 = 'AUK_OSFVEINFO'
}

$Script:OSDeviceMapping = @{
    0x00000000 = 'UNKNOWN'
    0x00010001 = 'BLOCKIO_HARDDISK'
    0x00010002 = 'BLOCKIO_REMOVABLEDISK'
    0x00010003 = 'BLOCKIO_CDROM'
    0x00010004 = 'BLOCKIO_PARTITION'
    0x00010005 = 'BLOCKIO_FILE'
    0x00010006 = 'BLOCKIO_RAMDISK'
    0x00010007 = 'BLOCKIO_VIRTUALHARDDISK'
    0x00020000 = 'SERIAL'
    0x00030000 = 'UDP'
    0x00040000 = 'VMBUS'
    0x00050000 = 'COMPOSITE'
    0x00060000 = 'CIMFS'
}

$Script:SIPolicyFlagMapping = @{
    0x00000001 = 'AllowedPrereleaseSigners'
    0x00000002 = 'AllowedKitsSigners'
    0x00000004 = 'EnabledUMCI'
    0x00000008 = 'EnabledBootMenuProtection'
    0x00000010 = 'AllowedUMCIDebugOptions'
    0x00000020 = 'EnabledUMCICacheDataVolumes'
    0x00000040 = 'AllowedSeQuerySigningPolicyExtension'
    0x00000080 = 'RequiredWHQL'
    0x00000100 = 'EnabledFilterEditedBootOptions'
    0x00000200 = 'DisabledUMCIUSN0Protection'
    0x00000400 = 'DisabledWinloadDebuggingModeMenu'
    0x00000800 = 'EnabledStrongCryptoForCodeIntegrity'
    0x00001000 = 'AllowedNonMicrosoftUEFIApplicationsForBitLocke'
    0x00002000 = 'EnabledAlwaysUsePolicy'
    0x00004000 = 'EnabledUMCITrustUSN0'
    0x00008000 = 'DisabledUMCIDebugOptionsTCBLowering'
    0x00010000 = 'EnabledAuditMode'
    0x00020000 = 'DisabledFlightSigning'
    0x00040000 = 'EnabledInheritDefaultPolicy'
    0x00080000 = 'EnabledUnsignedSystemIntegrityPolicy'
    0x00100000 = 'AllowedDebugPolicyAugmented'
    0x00200000 = 'RequiredEVSigners'
    0x00400000 = 'EnabledBootAuditOnFailure'
    0x00800000 = 'EnabledAdvancedBootOptionsMenu'
    0x01000000 = 'DisabledScriptEnforcement'
    0x02000000 = 'RequiredEnforceStoreApplications'
    0x04000000 = 'EnabledSecureSettingPolicy'
}

$Script:EventTypeMapping = @{
    [UInt32] 0                = 'EV_PREBOOT_CERT'          # The event field contains certificates such as the Validation Certificates.
    [UInt32] 1                = 'EV_POST_CODE'             # The digest field contains the SHA-1 hash of the POST portion of the BIOS. The event field SHOULD NOT contain the actual POST code but MAY contain informative information about the POST code.
    [UInt32] 2                = 'EV_UNUSED'                # The event type was never used and is considered reserved.
    [UInt32] 3                = 'EV_NO_ACTION'             # The event field contains informative data that was not extended into any PCR. The fields: pcrIndex and digest MUST contain the value 0.
    [UInt32] 4                = 'EV_SEPARATOR'             # Delimits actions taken during the Pre-Operating System State and the Operating System Present State
    # This will often be "WBCL" - Windows Boot Configuration Log (Microsoft's name for the TCG log)
    [UInt32] 5                = 'EV_ACTION'                # A specific action measured as a string defined in Section 10.4.3.
    [UInt32] 6                = 'EV_EVENT_TAG'             # The event field contains the structure defined in Section 10.4.2.1.
    [UInt32] 7                = 'EV_S_CRTM_CONTENTS'       # The digest field contains is the SHA-1 hash of the SCRTM. The event field SHOULD NOT contain the actual S-CRTM code but MAY contain informative information about the S-CRTM code.
    [UInt32] 8                = 'EV_S_CRTM_VERSION'        # The event field contains the version string of the SCRTM.
    [UInt32] 9                = 'EV_CPU_MICROCODE'         # The event field contains a descriptor of the microcode but the digest field contains the actual hash of the microcode patch that was applied.
    [UInt32] 10               = 'EV_PLATFORM_CONFIG_FLAGS' # The format and contents to be defined by the platform manufacturer. Examples of information contained in this event type are the capabilities of the platform?s measurements, whether the Owner has disabled measurements, etc.
    [UInt32] 11               = 'EV_TABLE_OF_DEVICES'      # The event field contains the Platform manufacturerprovided Table of Devices or other Platform manufacturer-defined information. The Platform manufacturer defines the content and format of the Table of Devices. The Host Platform Certificate may provide a reference to the meaning of these structures and data. This structure is measured into PCR[1] using the following.
    [UInt32] 12               = 'EV_COMPACT_HASH'          # This event is entered using the TCG_CompactHashLogExtendEvent. While it can be used by any function, it is typically used by IPL Code to measure events. The contents of the event field is specified by the caller but is not part of the measurement; rather, it is just informative.
    [UInt32] 13               = 'EV_IPL'                   # The digest field contains the SHA-1 hash of the IPL Code. The event field SHOULD NOT contain the actual IPL Code but MAY contain informative information about the IPL Code. Note: The digest may not cover the entire area hosting the IPL Image, but only the portion that contains the IPL Code. For example, if the IPL Image is a disk drive MBR, this MUST NOT include the portion of the MBR that contains the disk geometry.
    [UInt32] 14               = 'EV_IPL_PARTITION_DATA'    # The data and partition portion of the IPL Image.
    [UInt32] 15               = 'EV_NONHOST_CODE'          # The executable component of any Non-host Platform. The contents of the event field are defined by the manufacturer of the Non-host Platform.
    [UInt32] 16               = 'EV_NONHOST_CONFIG'        # The parameters associated with a Non-host Platform. The contents of the event field are defined by the manufacturer of the Non-host Platform.
    [UInt32] 17               = 'EV_NONHOST_INFO'          # The event is information about the presence of a Non-host Platform. This information could be, but is not required to be, information such as the Non-host Platform manufacturer, model, type, version, etc. The information and formatting is to be determined by the BIOS.
    [UInt32] 0x00000012       = 'EV_OMIT_BOOT_DEVICE_EVENTS'
    [UInt32] (2147483648 + 1) = 'EV_EFI_VARIABLE_DRIVER_CONFIG'    # EFI variables, either defined in the EFI spec or private, that typically do not change from boot-to-boot and contain system configuration information.
    [UInt32] (2147483648 + 2) = 'EV_EFI_VARIABLE_BOOT'             # This event is used to measure boot variables. The event field MUST contain a UEFI_VARIABLE_DATA structure
    [UInt32] (2147483648 + 3) = 'EV_EFI_BOOT_SERVICES_APPLICATION' # EFI application (e.g. EFI OSLoader)
    [UInt32] (2147483648 + 4) = 'EV_EFI_BOOT_SERVICES_DRIVER'      # EFI Boot Services Drivers from adapter or loaded by driver in adapter.
    [UInt32] (2147483648 + 5) = 'EV_EFI_RUNTIME_SERVICES_DRIVER'   # EFI Runtime drivers from adapter or loaded by driver in adapter.
    [UInt32] (2147483648 + 6) = 'EV_EFI_GPT_EVENT'                 # GPT Table
    [UInt32] (2147483648 + 7) = 'EV_EFI_ACTION'                    # Measurement of a specific string value that indicates a specific event occurred during the platform or OS boot process.
    [UInt32] (2147483648 + 8) = 'EV_EFI_PLATFORM_FIRMWARE_BLOB'    # The event MUST contain a UEFI_PLATFORM_FIRMWARE_BLOB structure
    [UInt32] (2147483648 + 9) = 'EV_EFI_HANDOFF_TABLES'            # Describes the measurement of industry-standard tables and data structure regions.
    [UInt32] 0x8000000Al      = 'EV_EFI_PLATFORM_FIRMWARE_BLOB2'
    [UInt32] 0x8000000Bl      = 'EV_EFI_HANDOFF_TABLES2'
    [UInt32] 0x80000010l      = 'EV_EFI_HCRTM_EVENT'            # This event is used to record an event for the digest extended to PCR[0] as part of an H-CRTM event.
    [UInt32] 0x800000E0l      = 'EV_EFI_VARIABLE_AUTHORITY'     # Documented here: https://docs.microsoft.com/en-us/windows-hardware/test/hlk/testref/trusted-execution-environment-efi-protocol
    [UInt32] 0x800000E1l      = 'EV_EFI_SPDM_FIRMWARE_BLOB'
    [UInt32] 0x800000E2l      = 'EV_EFI_SPDM_FIRMWARE_CONFIG'
    #----------------------------------PCR Event Types for Intel TXT
    [UInt32] 0x00000400l      = 'EV_TXT_EVENT_BASE'
    [UInt32] 0x00000401l      = 'EV_TXT_PCR_MAPPING'
    [UInt32] 0x00000402l      = 'EV_TXT_HASH_START'
    [UInt32] 0x00000403l      = 'EV_TXT_COMBINED_HASH'
    [UInt32] 0x00000404l      = 'EV_TXT_MLE_HASH'
    [UInt32] 0x0000040Al      = 'EV_TXT_BIOSAC_REG_DATA'
    [UInt32] 0x0000040Bl      = 'EV_TXT_CPU_SCRTM_STAT'
    [UInt32] 0x0000040Cl      = 'EV_TXT_LCP_CONTROL_HASH'
    [UInt32] 0x0000040Dl      = 'EV_TXT_ELEMENTS_HASH'
    [UInt32] 0x0000040El      = 'EV_TXT_STM_HASH'
    [UInt32] 0x0000040Fl      = 'EV_TXT_OSSINITDATA_CAP_HASH'
    [UInt32] 0x00000410l      = 'EV_TXT_SINIT_PUBKEY_HASH'
    [UInt32] 0x00000411l      = 'EV_TXT_LCP_HASH'
    [UInt32] 0x00000412l      = 'EV_TXT_LCP_DETAILS_HASH'
    [UInt32] 0x00000413l      = 'EV_TXT_LCP_AUTHORITIES_HASH'
    [UInt32] 0x00000414l      = 'EV_TXT_NV_INFO_HASH'
    [UInt32] 0x00000415l      = 'EV_TXT_COLD_BOOT_BIOS_HASH'
    [UInt32] 0x00000416l      = 'EV_TXT_KM_HASH'
    [UInt32] 0x00000417l      = 'EV_TXT_BPM_HASH'
    [UInt32] 0x00000418l      = 'EV_TXT_KM_INFO_HASH'
    [UInt32] 0x00000419l      = 'EV_TXT_BPM_INFO_HASH'
    [UInt32] 0x0000041Al      = 'EV_TXT_BOOT_POL_HASH'
    [UInt32] 0x000004FEl      = 'EV_TXT_RANDOM_VALUE'
    [UInt32] 0x000004FFl      = 'EV_TXT_CAP_VALUE'
    #----------------------------------PCR Event Types for AMD SecureLaunch
    [UInt32] 0x00008000l      = 'EV_AMD_SL_EVENT_BASE'
    [UInt32] 0x00008001l      = 'EV_AMD_SL_LOAD'
    [UInt32] 0x00008002l      = 'EV_AMD_SL_PSP_FW_SPLT'
    [UInt32] 0x00008003l      = 'EV_AMD_SL_TSME_RB_FUSE'
    [UInt32] 0x00008004l      = 'EV_AMD_SL_PUB_KEY'
    [UInt32] 0x00008005l      = 'EV_AMD_SL_SVN'
    [UInt32] 0x00008006l      = 'EV_AMD_SL_LOAD_1'
    [UInt32] 0x00008007l      = 'EV_AMD_SL_SEPARATOR'
}

$Script:DigestSizeMapping = @{
    'TPM_ALG_SHA1'     = 20
    'TPM_ALG_SHA256'   = 32
    'TPM_ALG_SHA384'   = 48
    'TPM_ALG_SHA512'   = 64
    'TPM_ALG_SM3_256'  = 32
    'TPM_ALG_SHA3_256' = 32
    'TPM_ALG_SHA3_384' = 48
    'TPM_ALG_SHA3_512' = 64
}

# To-do: expand out the device subtype parsers
$Script:DevicePathTypeMapping = @{
    [Byte] 1    = 'HARDWARE_DEVICE_PATH' # Hardware Device Path
    [Byte] 2    = 'ACPI_DEVICE_PATH'     # ACPI Device Path
    [Byte] 3    = 'MESSAGING_DEVICE_PATH'# Messaging Device Path
    [Byte] 4    = 'MEDIA_DEVICE_PATH'    # Media Device Path
    [Byte] 5    = 'BBS_DEVICE_PATH'      # BIOS Boot Specification Device Path
    [Byte] 0x7F = 'END_DEVICE_PATH_TYPE'
}

$Script:MediaDeviceSubTypeMapping = @{
    [Byte] 1 = 'MEDIA_HARDDRIVE_DP'    # Corresponding struct: HARDDRIVE_DEVICE_PATH
    [Byte] 2 = 'MEDIA_CDROM_DP'        # Corresponding struct: CDROM_DEVICE_PATH
    [Byte] 3 = 'MEDIA_VENDOR_DP'       # Corresponding struct: ?
    [Byte] 4 = 'MEDIA_FILEPATH_DP'     # Corresponding struct: FILEPATH_DEVICE_PATH
    [Byte] 5 = 'MEDIA_PROTOCOL_DP'     # Corresponding struct: MEDIA_PROTOCOL_DEVICE_PATH
    [Byte] 6 = 'MEDIA_PIWG_FW_FILE_DP' # Corresponding struct: MEDIA_FW_VOL_FILEPATH_DEVICE_PATH
    [Byte] 7 = 'MEDIA_PIWG_FW_VOL_DP'  # Corresponding struct: MEDIA_FW_VOL_DEVICE_PATH
    [Byte] 8 = 'MEDIA_RELATIVE_OFFSET_RANGE_DP' # Corresponding struct: MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH
    [Byte] 9 = 'MEDIA_RAM_DISK_DP'     # Corresponding struct: MEDIA_RAM_DISK_DEVICE_PATH
}

$Script:ACPIDeviceSubTypeMapping = @{
    [Byte] 1 = 'ACPI_DP'               # Corresponding struct: ACPI_HID_DEVICE_PATH
    [Byte] 2 = 'ACPI_EXTENDED_DP'      # Corresponding struct: ACPI_EXTENDED_HID_DEVICE_PATH
    [Byte] 3 = 'ACPI_ADR_DP'           # Corresponding struct: ACPI_ADR_DEVICE_PATH
}

# https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/DevicePath.h
$Script:HardwareDeviceSubTypeMapping = @{
    [Byte] 1 = 'HW_PCI_DP'             # Corresponding struct: PCI_DEVICE_PATH
    [Byte] 2 = 'HW_PCCARD_DP'          # Corresponding struct: PCCARD_DEVICE_PATH
    [Byte] 3 = 'HW_MEMMAP_DP'          # Corresponding struct: MEMMAP_DEVICE_PATH
    [Byte] 4 = 'HW_VENDOR_DP'          # Corresponding struct: VENDOR_DEVICE_PATH
    [Byte] 5 = 'HW_CONTROLLER_DP'      # Corresponding struct: CONTROLLER_DEVICE_PATH
    [Byte] 6 = 'HW_BMC_DP'             # Corresponding struct: BMC_DEVICE_PATH
}

$Script:MessagingDeviceSubTypeMapping = @{
    [Byte] 0x01 = 'MSG_ATAPI_DP'                # Corresponding struct: ATAPI_DEVICE_PATH
    [Byte] 0x02 = 'MSG_SCSI_DP'                 # Corresponding struct: SCSI_DEVICE_PATH
    [Byte] 0x03 = 'MSG_FIBRECHANNEL_DP'         # Corresponding struct: FIBRECHANNEL_DEVICE_PATH
    [Byte] 0x15 = 'MSG_FIBRECHANNELEX_DP'       # Corresponding struct: FIBRECHANNELEX_DEVICE_PATH
    [Byte] 0x04 = 'MSG_1394_DP'                 # Corresponding struct: F1394_DEVICE_PATH
    [Byte] 0x05 = 'MSG_USB_DP'                  # Corresponding struct: USB_DEVICE_PATH
    [Byte] 0x0f = 'MSG_USB_CLASS_DP'            # Corresponding struct: USB_CLASS_DEVICE_PATH
    [Byte] 0x10 = 'MSG_USB_WWID_DP'             # Corresponding struct: USB_WWID_DEVICE_PATH
    [Byte] 0x11 = 'MSG_DEVICE_LOGICAL_UNIT_DP'  # Corresponding struct: DEVICE_LOGICAL_UNIT_DEVICE_PATH
    [Byte] 0x12 = 'MSG_SATA_DP'                 # Corresponding struct: SATA_DEVICE_PATH
    [Byte] 0x06 = 'MSG_I2O_DP'                  # Corresponding struct: I2O_DEVICE_PATH
    [Byte] 0x0b = 'MSG_MAC_ADDR_DP'             # Corresponding struct: MAC_ADDR_DEVICE_PATH
    [Byte] 0x0c = 'MSG_IPv4_DP'                 # Corresponding struct: IPv4_DEVICE_PATH
    [Byte] 0x0d = 'MSG_IPv6_DP'                 # Corresponding struct: IPv6_DEVICE_PATH
    [Byte] 0x09 = 'MSG_INFINIBAND_DP'           # Corresponding struct: INFINIBAND_DEVICE_PATH
    [Byte] 0x0e = 'MSG_UART_DP'                 # Corresponding struct: UART_DEVICE_PATH
    [Byte] 0x20 = 'NVDIMM_NAMESPACE_DP'         # Corresponding struct: NVDIMM_NAMESPACE_DEVICE_PATH
    [Byte] 0x0a = 'MSG_VENDOR_DP'               # Corresponding struct: VENDOR_DEFINED_DEVICE_PATH (VENDOR_DEVICE_PATH)
    [Byte] 0x16 = 'MSG_SASEX_DP'                # Corresponding struct: SASEX_DEVICE_PATH
    [Byte] 0x17 = 'MSG_NVME_NAMESPACE_DP'       # Corresponding struct: NVME_NAMESPACE_DEVICE_PATH
    [Byte] 0x1f = 'MSG_DNS_DP'                  # Corresponding struct: DNS_DEVICE_PATH
    [Byte] 0x18 = 'MSG_URI_DP'                  # Corresponding struct: URI_DEVICE_PATH
    [Byte] 0x19 = 'MSG_UFS_DP'                  # Corresponding struct: UFS_DEVICE_PATH
    [Byte] 0x1a = 'MSG_SD_DP'                   # Corresponding struct: SD_DEVICE_PATH
    [Byte] 0x1d = 'MSG_EMMC_DP'                 # Corresponding struct: EMMC_DEVICE_PATH
    [Byte] 0x13 = 'MSG_ISCSI_DP'                # Corresponding struct: ISCSI_DEVICE_PATH
    [Byte] 0x14 = 'MSG_VLAN_DP'                 # Corresponding struct: VLAN_DEVICE_PATH
    [Byte] 0x1b = 'MSG_BLUETOOTH_DP'            # Corresponding struct: BLUETOOTH_DEVICE_PATH
    [Byte] 0x1c = 'MSG_WIFI_DP'                 # Corresponding struct: WIFI_DEVICE_PATH
    [Byte] 0x1e = 'MSG_BLUETOOTH_LE_DP'         # Corresponding struct: BLUETOOTH_LE_DEVICE_PATH
}

$Script:MessagingVendorMapping = @{
    'E0C14753-F9BE-11D2-9A0C-0090273FC14D' = 'EFI_PC_ANSI_GUID'
    'DFA66065-B419-11D3-9A2D-0090273FC14D' = 'EFI_VT_100_GUID'
    '7BAEC70B-57E0-4C76-8E87-2F9E28088343' = 'EFI_VT_100_PLUS_GUID'
    'AD15A0D6-8BEC-4ACF-A073-D01DE77E2D88' = 'EFI_VT_UTF8_GUID'
}

$Script:PartitionGUIDMapping = @{
    'EBD0A0A2-B9E5-4433-87C0-68B6B72699C7' = 'PARTITION_BASIC_DATA_GUID'
    '57434F53-4DF9-45B9-8E9E-2370F006457C' = 'PARTITION_BSP_GUID'
    'DB97DBA9-0840-4BAE-97F0-FFB9A327C7E1' = 'PARTITION_CLUSTER_GUID'
    '57434F53-94CB-43F0-A533-D73C10CFA57D' = 'PARTITION_DPP_GUID'
    '00000000-0000-0000-0000-000000000000' = 'PARTITION_ENTRY_UNUSED_GUID'
    'AF9B60A0-1431-4F62-BC68-3311714A69AD' = 'PARTITION_LDM_DATA_GUID'
    '5808C8AA-7E8F-42E0-85D2-E1E90434CFB3' = 'PARTITION_LDM_METADATA_GUID'
    '424CA0E2-7CB2-4FB9-8143-C52A99398BC6' = 'PARTITION_LEGACY_BL_GUID'
    '424C3E6C-D79F-49CB-935D-36D71467A288' = 'PARTITION_LEGACY_BL_GUID_BACKUP'
    '57434F53-8F45-405E-8A23-186D8A4330D3' = 'PARTITION_MAIN_OS_GUID'
    'DE94BBA4-06D1-4D40-A16A-BFD50179D6AC' = 'PARTITION_MSFT_RECOVERY_GUID'
    'E3C9E316-0B5C-4DB8-817D-F92DF00215AE' = 'PARTITION_MSFT_RESERVED_GUID'
    'CADDEBF1-4400-4DE8-B103-12117DCF3CCF' = 'PARTITION_MSFT_SNAPSHOT_GUID'
    '57434F53-23F2-44D5-A830-67BBDAA609F9' = 'PARTITION_OS_DATA_GUID'
    '8967A686-96AA-6AA8-9589-A84256541090' = 'PARTITION_PATCH_GUID'
    '57434F53-7FE0-4196-9B42-427B51643484' = 'PARTITION_PRE_INSTALLED_GUID'
    'EEFF8352-DD2A-44DB-AE83-BEE1CF7481DC' = 'PARTITION_SBL_CACHE_SSD_GUID'
    'DCC0C7C1-55AD-4F17-9D43-4BC776E0117E' = 'PARTITION_SBL_CACHE_SSD_RESERVED_GUID'
    '03AAA829-EBFC-4E7E-AAC9-C4D76C63B24B' = 'PARTITION_SBL_CACHE_HDD_GUID'
    '57434F53-432E-4014-AE4C-8DEAA9C0006A' = 'PARTITION_SERVICING_FILES_GUID'
    '57434F53-C691-4A05-BB4E-703DAFD229CE' = 'PARTITION_SERVICING_METADATA_GUID'
    '57434F53-4B81-460B-A319-FFB6FE136D14' = 'PARTITION_SERVICING_RESERVE_GUID'
    '57434F53-E84D-4E84-AAF3-ECBBBD04B9DF' = 'PARTITION_SERVICING_STAGING_ROOT_GUID'
    'E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D' = 'PARTITION_SPACES_GUID'
    'E7ADDCB4-DC34-4539-9A76-EBBD07BE6F7E' = 'PARTITION_SPACES_DATA_GUID'
    'C12A7328-F81F-11D2-BA4B-00A0C93EC93B' = 'PARTITION_SYSTEM_GUID'
    '57434F53-E3E3-4631-A5C5-26D2243873AA' = 'PARTITION_WINDOWS_SYSTEM_GUID'
}
#endregion

function ConvertTo-CertificateInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Byte[]]
        $CertificateData,
        [Parameter()]
        [switch]
        $Details
    )

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificateData)
    $result = @{
        Subject      = $cert.Subject
        Issuer       = $cert.Issuer
        SerialNumber = $cert.SerialNumber
        NotBefore    = [System.TimeZoneInfo]::ConvertTimeToUtc($cert.NotBefore).ToString("o")
        NotAfter     = [System.TimeZoneInfo]::ConvertTimeToUtc($cert.NotAfter).ToString("o")
        Thumbprint   = $cert.Thumbprint
    }
    if ($Details) {
        $result += @{
            Version            = $cert.Version
            SignatureAlgorithm = $cert.SignatureAlgorithm
            PublicKey          = @{
                Oid               = $cert.PublicKey.Oid
                EncodedKeyValue   = $cert.PublicKey.EncodedKeyValue.Format($false)
                EncodedParameters = $cert.PublicKey.EncodedParameters.Format($false)
            }
            Extensions         = $cert.Extensions | ForEach-Object {
                @(
                    $_.GetType().Name
                    if ($_.Critical) {
                        "Critical"
                    }
                    $_.Format($false)
                ) -join "  "
            }
        }
    }

    return $result
}

# Helper function to retrieve SIPA events - i.e. Windows-specific PCR measurements
# I still have no clue what SIPA refers to. I use it because it's referenced all over wbcl.h.
# This function should not be exported.
function Get-SIPAEventData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Byte[]]
        $SIPAEventBytes
    )

    # We need to identify container structures and recurse accordingly.
    $ContainerType = 0x00010000

    $EventMemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(, $SIPAEventBytes)
    $EventBinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $EventMemoryStream, ([Text.Encoding]::Unicode)

    $evs = while (($EventBinaryReader.BaseStream.Position) -lt $SIPAEventBytes.Count) {
        $SIPAEventTypeVal = $EventBinaryReader.ReadInt32()
        $SIPAEventType = $SIPAEventMapping[$SIPAEventTypeVal]

        $SIPAEventSize = $EventBinaryReader.ReadUInt32()
        $EventBytes = $EventBinaryReader.ReadBytes($SIPAEventSize)

        # All SIPA event types _should_ be defined but just in case one isn't, print it out in hex.
        if (-not $SIPAEventType) { $SIPAEventType = "0x$($SIPAEventTypeVal.ToString('X8'))" }

        if ($SIPAEventType -eq 'NoAuthority' -or $SIPAEventType -eq 'AuthorityPubKey') {
            switch ($SIPAEventType) {
                'NoAuthority' {
                    [PSCustomObject] @{
                        #Category = 'Authority'
                        SIPAEventType = $SIPAEventType
                        NoAuthority   = $EventBytes
                    }
                }

                'AuthorityPubKey' {
                    $AuthorityPubKey = $null
                    if ([Environment]::Version.Major -ge 6) {
                        $bytes = 0
                        $pk = [System.Security.Cryptography.X509Certificates.PublicKey]::CreateFromSubjectPublicKeyInfo($EventBytes, [ref] $bytes)
                        $AuthorityPubKey = @{
                            Oid               = $pk.Oid
                            EncodedKeyValue   = $pk.EncodedKeyValue.Format($false)
                            EncodedParameters = $pk.EncodedParameters.Format($false)
                        }
                    }
                    else {
                        $AuthorityPubKey = ($EventBytes | ForEach-Object { $_.ToString('X2') }) -join ':'
                    }
                    [PSCustomObject] @{
                        #Category = 'Authority'
                        SIPAEventType   = $SIPAEventType
                        AuthorityPubKey = $AuthorityPubKey
                    }
                }
            }
        }
        elseif (($SIPAEventTypeVal -band 0x000F0000) -eq $ContainerType) {
            switch ($SIPAEventType) {
                'LoadedModuleAggregation' {
                    $ContainerEvents = Get-SIPAEventData -SIPAEventBytes $EventBytes
                    $LoadedModule = @{}
                    foreach ($ev in $ContainerEvents) {
                        $LoadedModule[$ev.SIPAEventType] = $ev.SIPAEventData
                    }

                    [PSCustomObject] @{
                        #Category = 'Authority'
                        SIPAEventType = $SIPAEventType
                        LoadedModule  = $LoadedModule
                    }
                }

                default {
                    [PSCustomObject] @{
                        #Category = 'Container'
                        SIPAEventType = $SIPAEventType
                        SIPAEventData = Get-SIPAEventData -SIPAEventBytes $EventBytes
                    }
                }
            }
        }
        else {
            # Each SIPA event data structure will differ depending on the type.
            # Many of these data types are not formally defined but can be easily inferred.
            # If the strucutre is not explicitly stated, it is inferred from multiple events.
            switch ($SIPAEventType) {
                'Information' { $EventData = $EventBytes; $Category = 'Information' }
                'BootCounter' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'Information' }
                'TransferControl' {
                    $TransferControl = [BitConverter]::ToUInt32($EventBytes, 0)
                    $TransferControlText = $TransferControlMapping[$TransferControl]
                    if (!$TransferControlText) {
                        $TransferControlText = $TransferControl.ToString('X8')
                    }

                    $Category = 'Information'

                    $EventData = $TransferControlText
                }
                'ApplicationReturn' { $EventData = $EventBytes; $Category = 'Information' }
                'BitlockerUnlock' {
                    $FvebUnlockFlag = [BitConverter]::ToUInt32($EventBytes, 0)
                    $Category = 'Information'
                    $FvebUnlockFlags = New-Object 'System.Collections.Generic.List[System.String]'
                    foreach ($f in $Script:FvebUnlockFlagMapping.GetEnumerator()) {
                        if ($FvebUnlockFlag -band $f.Key) {
                            $FvebUnlockFlags.Add($f.Value)
                            $FvebUnlockFlag = $FvebUnlockFlag -band (-bnot $f.key)
                        }
                    }
                    if ($FvebUnlockFlag -ne 0) {
                        $FvebUnlockFlags.Add($FvebUnlockFlag.ToString('X8'))
                    }
                    $EventData = [PSCustomObject]@{
                        Flags = $FvebUnlockFlags
                    }
                }
                'EventCounter' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'Information' }
                'CounterID' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'Information' }
                'MORBitNotCancelable' { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'Information' }
                'ApplicationSVN' { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'Information' }
                'SVNChainStatus' { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'Information' }
                # MemoryOverwriteRequest - Introduced in the TCG Platform Reset Attack Mitigation Specification
                'MORBitAPIStatus' { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'Information' }
                'BootDebugging' { $EventData = [Bool] $EventBytes[0]; $Category = 'PreOSParameter' }

                'BootRevocationList' {
                    # SIPAEVENT_REVOCATION_LIST_PAYLOAD structure

                    $CreationTime = [datetime]::FromFileTimeUtc([BitConverter]::ToUInt64($EventBytes, 0)).ToString("o")
                    $DigestLength = [BitConverter]::ToUInt32($EventBytes, 8)
                    $HashAlgorithm = $DigestAlgorithmMapping[[BitConverter]::ToUInt16($EventBytes, 0x0C)]
                    $Digest = [BitConverter]::ToString($EventBytes[0x0E..(0x0E + $DigestLength - 1)]).Replace('-', '')

                    $Category = 'PreOSParameter'

                    $EventData = [PSCustomObject] @{
                        CreationTime  = $CreationTime
                        HashAlgorithm = $HashAlgorithm
                        Digest        = $Digest
                    }
                }

                'OSKernelDebug' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'CodeIntegrity' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'TestSigning' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'DataExecutionPrevention' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'SafeMode' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'WinPE' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'PhysicalAddressExtension' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'OSDevice' { $EventData = $OSDeviceMapping[[BitConverter]::ToInt32($EventBytes, 0)]; $Category = 'OSParameter' }
                'SystemRoot' { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'OSParameter' }
                'HypervisorLaunchType' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'HypervisorPath' { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'OSParameter' }
                'HypervisorIOMMUPolicy' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'HypervisorDebug' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'DriverLoadPolicy' { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'OSParameter' }

                'SIPolicy' {
                    # SIPAEVENT_SI_POLICY_PAYLOAD structure

                    $Revision = [Int32][BitConverter]::ToInt16($EventBytes, 0)
                    $Build = [Int32][BitConverter]::ToInt16($EventBytes, 2)
                    $Minor = [Int32][BitConverter]::ToInt16($EventBytes, 4)
                    $Major = [Int32][BitConverter]::ToInt16($EventBytes, 6)
                    $PolicyVersion = New-Object -TypeName Version -ArgumentList @($Major, $Minor, $Build, $Revision)

                    $PolicyNameLength = [BitConverter]::ToInt16($EventBytes, 8)
                    $HashAlgorithm = $DigestAlgorithmMapping[[BitConverter]::ToUInt16($EventBytes, 0x0A)]

                    $DigestLength = [BitConverter]::ToUInt16($EventBytes, 0x0C)
                    $DigestIndex = 0x10 + $PolicyNameLength

                    $PolicyName = [Text.Encoding]::Unicode.GetString($EventBytes[0x10..($DigestIndex - 1)]).TrimEnd(@(0))
                    $Digest = [BitConverter]::ToString($EventBytes[($DigestIndex)..($DigestIndex + $DigestLength - 1)]).Replace('-', '')

                    $Category = 'OSParameter'

                    $EventData = [PSCustomObject] @{
                        PolicyVersion = $PolicyVersion
                        PolicyName    = $PolicyName
                        HashAlgorithm = $HashAlgorithm
                        Digest        = $Digest
                    }
                }

                'HypervisorMMIONXPolicy' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'HypervisorMSRFilterPolicy' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }
                'VSMLaunchType' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'OSParameter' }

                'OSRevocationList' {
                    # SIPAEVENT_REVOCATION_LIST_PAYLOAD structure

                    $CreationTime = [datetime]::FromFileTimeUtc([BitConverter]::ToUInt64($EventBytes, 0)).ToString("o")
                    $DigestLength = [BitConverter]::ToUInt32($EventBytes, 8)
                    $HashAlgorithm = $DigestAlgorithmMapping[[BitConverter]::ToUInt16($EventBytes, 0x0C)]
                    $Digest = [BitConverter]::ToString($EventBytes[0x0E..(0x0E + $DigestLength - 1)]).Replace('-', '')

                    $Category = 'OSParameter'

                    $EventData = [PSCustomObject] @{
                        CreationTime  = $CreationTime
                        HashAlgorithm = $HashAlgorithm
                        Digest        = $Digest
                    }
                }

                'SMTStatus' {
                    $SMTStatus = [BitConverter]::ToUInt32($EventBytes, 0)
                    $SMTStatusText = $SMTStatusTextMapping[$SMTStatus]
                    if (!$SMTStatusText) {
                        $SMTStatusText = $SMTStatus.ToString('X8')
                    }

                    $Category = 'OSParameter'

                    $EventData = $SMTStatusText
                }

                'VSMIDKInfo' {
                    # SIPAEVENT_VSM_IDK_INFO_PAYLOAD structure

                    # Type: VSM_IDK_ALG_ID (I can't find this defined anywhere. I'm personally not worried about it. IDK what "IDK" is)
                    # This should only be 1.
                    $KeyAlgID = [BitConverter]::ToUInt32($EventBytes, 0)
                    $null = [BitConverter]::ToUInt32($EventBytes, 4) # KeyBitLength
                    $PublicExpLengthBytes = [BitConverter]::ToUInt32($EventBytes, 8)
                    $ModulusSizeBytes = [BitConverter]::ToUInt32($EventBytes, 0x0C)

                    $ModulusIndex = 0x10 + $PublicExpLengthBytes

                    [Byte[]] $PublicExponent = $EventBytes[0x10..($ModulusIndex - 1)]
                    [Byte[]] $Modulus = $EventBytes[($ModulusIndex)..($ModulusIndex + $ModulusSizeBytes - 1)]

                    $Category = 'OSParameter'

                    $EventData = [PSCustomObject] @{
                        KeyAlgID       = $KeyAlgID
                        PublicExponent = ($PublicExponent | ForEach-Object { $_.ToString('X2') }) -join ':'
                        Modulus        = ($Modulus | ForEach-Object { $_.ToString('X2') }) -join ':'
                    }
                }

                'FlightSigning' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'PagefileEncryptionEnabled' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }

                'VSMIDKSInfo' {
                    # SIPAEVENT_VSM_IDK_INFO_PAYLOAD structure

                    # Type: VSM_IDK_ALG_ID (I can't find this defined anywhere. I'm personally not worried about it. IDK what "IDK" is)
                    # This should only be 1.
                    $KeyAlgID = [BitConverter]::ToUInt32($EventBytes, 0)
                    $null = [BitConverter]::ToUInt32($EventBytes, 4) # KeyBitLength
                    $PublicExpLengthBytes = [BitConverter]::ToUInt32($EventBytes, 8)
                    $ModulusSizeBytes = [BitConverter]::ToUInt32($EventBytes, 0x0C)

                    $ModulusIndex = 0x10 + $PublicExpLengthBytes

                    [Byte[]] $PublicExponent = $EventBytes[0x10..($ModulusIndex - 1)]
                    [Byte[]] $Modulus = $EventBytes[($ModulusIndex)..($ModulusIndex + $ModulusSizeBytes - 1)]

                    $Category = 'OSParameter'

                    $EventData = [PSCustomObject] @{
                        KeyAlgID       = $KeyAlgID
                        PublicExponent = ($PublicExponent | ForEach-Object { $_.ToString('X2') }) -join ':'
                        Modulus        = ($Modulus | ForEach-Object { $_.ToString('X2') }) -join ':'
                    }
                }

                'HibernationDisabled' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'DumpsDisabled' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                'DumpEncryptionEnabled' { $EventData = [Bool] $EventBytes[0]; $Category = 'OSParameter' }
                # SHA-256 digest of thefollowing regkey value:
                # CurrentControlSet\Control\CrashControl\EncryptionCertificates\Certificate.1::PublicKey
                'DumpEncryptionKeyDigest' { $EventData = $EventBytes; $Category = 'OSParameter' }
                'LSAISOConfig' { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'OSParameter' }
                'FilePath' { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'LoadedImage' }
                'SIPAEventData' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'LoadedImage' }
                'HashAlgorithmID' { $EventData = $HashAlgorithmMapping[[BitConverter]::ToInt32($EventBytes, 0)]; $Category = 'LoadedImage' }
                'AuthenticodeHash' { $EventData = [BitConverter]::ToString($EventBytes).Replace('-', ''); $Category = 'LoadedImage' }
                'AuthorityIssuer' { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'LoadedImage' }
                'AuthoritySerial' { $EventData = [BitConverter]::ToString($EventBytes).Replace('-', ''); $Category = 'LoadedImage' }
                'ImageBase' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'LoadedImage' }
                'ImageSize' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'LoadedImage' }
                'AuthorityPublisher' { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'LoadedImage' }
                'AuthoritySHA1Thumbprint' { $EventData = [BitConverter]::ToString($EventBytes).Replace('-', ''); $Category = 'LoadedImage' }
                'ImageValidated' { $EventData = [Bool] $EventBytes[0]; $Category = 'LoadedImage' }
                'ModuleSVN' { $EventData = [BitConverter]::ToUInt32($EventBytes, 0); $Category = 'LoadedImage' }
                'AIKID' { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'Trustpoint' }
                'AIKPubDigest' { $EventData = [BitConverter]::ToString($EventBytes).Replace('-', ''); $Category = 'Trustpoint' }
                'Quote' { $EventData = ($EventBytes | ForEach-Object { $_.ToString('X2') }) -join ':'; $Category = 'Trustpoint' }
                'QuoteSignature' { $EventData = ($EventBytes | ForEach-Object { $_.ToString('X2') }) -join ':'; $Category = 'Trustpoint' }
                'VBSVSMRequired' { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'VBSSecurebootRequired' { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'VBSIOMMURequired' { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'VBSNXRequired' { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'VBSMSRFilteringRequired' { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'VBSMandatoryEnforcement' { $EventData = $EventBytes; $Category = 'VBS' }
                'VBSHVCIPolicy' { $EventData = [BitConverter]::ToUInt64($EventBytes, 0); $Category = 'VBS' }
                'VBSMicrosoftBootChainRequired' { $EventData = [Bool] $EventBytes[0]; $Category = 'VBS' }
                'ELAMKeyname' { $EventData = [Text.Encoding]::Unicode.GetString($EventBytes).TrimEnd(@(0)); $Category = 'ELAM' }
                'ELAMMeasured' { $EventData = [BitConverter]::ToString($EventBytes).Replace('-', ''); $Category = 'ELAM' }
                'ELAMConfiguration' { $EventData = $EventBytes; $Category = 'ELAM' }
                'ELAMPolicy' { $EventData = $EventBytes; $Category = 'ELAM' }

                'KSRSignature' {
                    # SIPAEVENT_REVOCATION_LIST_PAYLOAD

                    $Category = 'KSR'

                    $SignatureLength = [BitConverter]::ToUInt32($EventBytes, 4)
                    [Byte[]] $Signature = $EventBytes[8..(8 + $SignatureLength - 1)]

                    $EventData = [PSCustomObject] @{
                        SignAlgID       = [BitConverter]::ToUInt32($EventBytes, 0)
                        SignatureLength = $SignatureLength
                        Signature       = ($Signature | ForEach-Object { $_.ToString('X2') }) -join ':'
                    }
                }

                'SBCPInfo' {
                    $Category = 'SBCP'
                    $PayloadVersion = [BitConverter]::ToUInt32($EventBytes, 0)

                    switch ($PayloadVersion) {
                        1 {
                            # SIPAEVENT_SBCP_INFO_PAYLOAD_V1
                            $VarDataOffset = [BitConverter]::ToUInt32($EventBytes, 4)
                            $HashAlgID = [BitConverter]::ToUInt16($EventBytes, 8)
                            $DigestLength = [BitConverter]::ToUInt16($EventBytes, 10)
                            [Byte[]] $DigestBytes = $EventBytes[$VarDataOffset..($VarDataOffset + $DigestLength - 1)]

                            $OptionsFlag = [BitConverter]::ToUInt32($EventBytes, 12)
                            $OptionsFlags = [System.Collections.Generic.List[string]]::new()
                            foreach ($f in $Script:SIPolicyFlagMapping.GetEnumerator()) {
                                if ($OptionsFlag -band $f.Key) {
                                    $OptionsFlags.Add($f.Value)
                                    $OptionsFlag = $OptionsFlag -band (-bnot $f.key)
                                }
                            }
                            if ($OptionsFlag -ne 0) {
                                $OptionsFlags.Add($OptionsFlag.ToString('X8'))
                            }

                            $EventData = [PSCustomObject] @{
                                HashAlg      = $DigestAlgorithmMapping[$HashAlgID]
                                Options      = $OptionsFlags
                                SignersCount = [BitConverter]::ToUInt32($EventBytes, 16)
                                Digest       = [BitConverter]::ToString($DigestBytes).Replace('-', '')
                            }

                            if ($GatherSBCP) {
                                Import-Module .\GetSecureBootPolicy.ps1 -Force
                                $policyData = Get-SecureBootPolicy
                                if ($policyData.PolicyHash -ieq $EventData.Digest) {
                                    $policyData = Select-Object -InputObject $policyData -ExcludeProperty PolicyBytes
                                    Add-Member -InputObject $EventData -MemberType NoteProperty -Name PolicyData -Value $policyData
                                }
                            }
                        }

                        default {
                            $EventData = $EventBytes
                        }
                    }
                }

                default {
                    $Category = 'Uncategorized'
                    $EventData = $EventBytes
                }
            }

            [PSCustomObject] @{
                #Category = $Category
                SIPAEventType = $SIPAEventType
                SIPAEventData = $EventData
            }
        }
    }

    $EventBinaryReader.Close()
    return $evs
}

function Get-EfiDevicePathProtocol {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Byte[]]
        $DevicePathBytes
    )

    if (!$DevicePathBytes.Count) {
        return $null
    }

    $MoreToParse = $True
    $FilePathEntryIndex = 0

    $FilePathList = while ($MoreToParse) {
        # Parse the EFI_DEVICE_PATH_PROTOCOL struct.

        $DevicePathType = $DevicePathTypeMapping[$DevicePathBytes[$FilePathEntryIndex]]
        $Length = [BitConverter]::ToUInt16($DevicePathBytes, $FilePathEntryIndex + 2)
        [Byte[]] $DataBytes = $DevicePathBytes[($FilePathEntryIndex + 4)..($FilePathEntryIndex + $Length - 1)]

        switch ($DevicePathType) {
            'HARDWARE_DEVICE_PATH' {
                $DeviceSubType = $HardwareDeviceSubTypeMapping[$DevicePathBytes[$FilePathEntryIndex + 1]]

                switch ($DeviceSubType) {
                    'HW_PCI_DP' {
                        $Function = $DevicePathBytes[$FilePathEntryIndex + 4 + 0]
                        $Device = $DevicePathBytes[$FilePathEntryIndex + 4 + 1]

                        $DeviceInfo = [PSCustomObject] @{
                            Function = $Function
                            Device   = $Device
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'HW_PCCARD_DP' {
                        $FunctionNumber = $DevicePathBytes[$FilePathEntryIndex + 4 + 0]

                        $DeviceInfo = [PSCustomObject] @{
                            FunctionNumber = $FunctionNumber
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'HW_MEMMAP_DP' {
                        $MemoryType = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 0)
                        $StartingAddress = [BitConverter]::ToUInt64($DevicePathBytes, $FilePathEntryIndex + 4 + 4)
                        $EndingAddress = [BitConverter]::ToUInt64($DevicePathBytes, $FilePathEntryIndex + 4 + 12)

                        $DeviceInfo = [PSCustomObject] @{
                            MemoryType      = $MemoryType
                            StartingAddress = $StartingAddress
                            EndingAddress   = $EndingAddress
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'HW_VENDOR_DP' {
                        $Guid = [Guid][byte[]] $DevicePathBytes[($FilePathEntryIndex + 4)..($FilePathEntryIndex + 4 + 15)]
                        $Data = $DevicePathBytes[($FilePathEntryIndex + 4 + 15)..($FilePathEntryIndex + $Length - 1)]
                        $Data = [BitConverter]::ToString($Data).Replace('-', ':')

                        $DeviceInfo = [PSCustomObject] @{
                            Guid = $Guid
                            Data = $Data
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'HW_CONTROLLER_DP' {
                        $ControllerNumber = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 0)

                        $DeviceInfo = [PSCustomObject] @{
                            ControllerNumber = $ControllerNumber
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'HW_BMC_DP' {
                        $InterfaceType = $DevicePathBytes[$FilePathEntryIndex + 4 + 0]
                        $BaseAddress = [BitConverter]::ToUInt64($DevicePathBytes, $FilePathEntryIndex + 4 + 1)

                        $DeviceInfo = [PSCustomObject] @{
                            InterfaceType = $InterfaceType
                            BaseAddress   = $BaseAddress
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    default {
                        $DeviceSubType = $DevicePathBytes[$FilePathEntryIndex + 1].ToString('X2')
                        $DeviceInfo = [PSCustomObject] @{ RawDeviceBytes = $DataBytes }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }
                }
            }

            'ACPI_DEVICE_PATH' {
                $DeviceSubType = $ACPIDeviceSubTypeMapping[$DevicePathBytes[$FilePathEntryIndex + 1]]

                switch ($DeviceSubType) {
                    'ACPI_DP' {
                        $HID = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 0)
                        $UID = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 4)

                        $DeviceInfo = [PSCustomObject] @{
                            HID = $HID # Device's PnP hardware ID stored in a numeric 32-bit
                            # compressed EISA-type ID. This value must match the
                            # corresponding _HID in the ACPI name space.
                            UID = $UID # Unique ID that is required by ACPI if two devices have the
                            # same _HID. This value must also match the corresponding
                            # _UID/_HID pair in the ACPI name space.
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'ACPI_EXTENDED_DP' {
                        $HID = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 0)
                        $UID = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 4)
                        $CID = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 8)

                        $DeviceInfo = [PSCustomObject] @{
                            HID = $HID
                            UID = $UID
                            CID = $CID # Device's compatible PnP hardware ID stored in a numeric
                            # 32-bit compressed EISA-type ID.
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'ACPI_ADR_DP' {
                        $ADR = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 0)

                        $DeviceInfo = [PSCustomObject] @{
                            ADR = $ADR # For video output devices the value of this
                            # field comes from Table B-2 of the ACPI 3.0 specification.
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    default {
                        $DeviceSubType = $DevicePathBytes[$FilePathEntryIndex + 1].ToString('X2')
                        $DeviceInfo = [PSCustomObject] @{ RawDeviceBytes = $DataBytes }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }
                }
            }

            'MEDIA_DEVICE_PATH' {
                $DeviceSubType = $MediaDeviceSubTypeMapping[$DevicePathBytes[$FilePathEntryIndex + 1]]

                switch ($DeviceSubType) {
                    'MEDIA_HARDDRIVE_DP' {
                        $PartitionNumber = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 0)
                        $PartitionStart = [BitConverter]::ToUInt64($DevicePathBytes, $FilePathEntryIndex + 4 + 4)
                        $PartitionSize = [BitConverter]::ToUInt64($DevicePathBytes, $FilePathEntryIndex + 4 + 4 + 8)

                        $SignatureIndex = $FilePathEntryIndex + 4 + 4 + 8 + 8
                        [Byte[]] $SignatureBytes = $DevicePathBytes[$SignatureIndex..($SignatureIndex + 16 - 1)]
                        $MBRType = @{ [Byte] 1 = 'MBR_TYPE_PCAT'; [Byte] 2 = 'MBR_TYPE_EFI_PARTITION_TABLE_HEADER' }[$DevicePathBytes[$SignatureIndex + 16]]
                        $SignatureType = @{ [Byte] 0 = 'NO_DISK_SIGNATURE'; [Byte] 1 = 'SIGNATURE_TYPE_MBR'; [Byte] 2 = 'SIGNATURE_TYPE_GUID' }[$DevicePathBytes[$SignatureIndex + 16 + 1]]
                        $Signature = $null
                        switch ($SignatureType) {
                            'SIGNATURE_TYPE_MBR' {
                                $Signature = [BitConverter]::ToUInt32($SignatureBytes, 0).ToString('X8')
                            }
                            'SIGNATURE_TYPE_GUID' {
                                $Signature = [guid]$SignatureBytes
                            }
                            default {
                                $Signature = ($SignatureBytes | ForEach-Object { $_.ToString('X2') }) -join ':'
                            }
                        }

                        $DeviceInfo = [PSCustomObject] @{
                            PartitionNumber = $PartitionNumber
                            PartitionStart  = $PartitionStart
                            PartitionSize   = $PartitionSize
                            Signature       = $Signature
                            MBRType         = $MBRType
                            SignatureType   = $SignatureType
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }


                    'MEDIA_FILEPATH_DP' {
                        $PathName = [Text.Encoding]::Unicode.GetString($DataBytes).TrimEnd(@(0))
                        $DeviceInfo = [PSCustomObject] @{ PathName = $PathName }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'MEDIA_PIWG_FW_VOL_DP' {
                        $DeviceInfo = [PSCustomObject] @{ FvName = [Guid] $DataBytes }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'MEDIA_PIWG_FW_FILE_DP' {
                        $DeviceInfo = [PSCustomObject] @{ FvFileName = [Guid] $DataBytes }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    default {
                        $DeviceSubType = $DevicePathBytes[$FilePathEntryIndex + 1].ToString('X2')
                        $DeviceInfo = [PSCustomObject] @{ RawDeviceBytes = $DataBytes }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }
                }
            }

            'MESSAGING_DEVICE_PATH' {
                $DeviceSubType = $MessagingDeviceSubTypeMapping[$DevicePathBytes[$FilePathEntryIndex + 1]]

                # too much effort to parse them all...
                switch ($DeviceSubType) {
                    'MSG_ATAPI_DP' {
                        $PrimarySecondary = $DevicePathBytes[$FilePathEntryIndex + 4 + 0]
                        $SlaveMaster = $DevicePathBytes[$FilePathEntryIndex + 4 + 1]
                        $Lun = [BitConverter]::ToUInt16($DevicePathBytes, $FilePathEntryIndex + 4 + 2)

                        $DeviceInfo = [PSCustomObject] @{
                            PrimarySecondary = $PrimarySecondary
                            SlaveMaster      = $SlaveMaster
                            Lun              = $Lun
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'MSG_SCSI_DP' {
                        $Pun = [BitConverter]::ToUInt16($DevicePathBytes, $FilePathEntryIndex + 4 + 0)
                        $Lun = [BitConverter]::ToUInt16($DevicePathBytes, $FilePathEntryIndex + 4 + 2)

                        $DeviceInfo = [PSCustomObject] @{
                            Pun = $Pun
                            Lun = $Lun
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'MSG_USB_DP' {
                        $ParentPortNumber = $DevicePathBytes[$FilePathEntryIndex + 4 + 0]
                        $InterfaceNumber = $DevicePathBytes[$FilePathEntryIndex + 4 + 1]

                        $DeviceInfo = [PSCustomObject] @{
                            ParentPortNumber = $ParentPortNumber
                            InterfaceNumber  = $InterfaceNumber
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'MSG_SATA_DP' {
                        $HBAPortNumber = [BitConverter]::ToUInt16($DevicePathBytes, $FilePathEntryIndex + 4 + 0)
                        $PortMultiplierPortNumber = [BitConverter]::ToUInt16($DevicePathBytes, $FilePathEntryIndex + 4 + 2)
                        $Lun = [BitConverter]::ToUInt16($DevicePathBytes, $FilePathEntryIndex + 4 + 4)

                        $DeviceInfo = [PSCustomObject] @{
                            HBAPortNumber            = $HBAPortNumber
                            PortMultiplierPortNumber = $PortMultiplierPortNumber
                            Lun                      = $Lun
                            HBADirectConnect         = !!($HBAPortNumber -band 0x8000)  # SATA_HBA_DIRECT_CONNECT_FLAG
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'MSG_VENDOR_DP' {
                        $Guid = [Guid][byte[]] $DevicePathBytes[($FilePathEntryIndex + 4)..($FilePathEntryIndex + 4 + 15)]
                        $Data = $DevicePathBytes[($FilePathEntryIndex + 4 + 15)..($FilePathEntryIndex + $Length - 1)]
                        $Data = [BitConverter]::ToString($Data).Replace('-', '')

                        $DeviceInfo = [PSCustomObject] @{
                            Guid   = $Guid
                            Vendor = $PartitionGUIDMapping[$Guid]
                            Data   = $Data
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    'MSG_NVME_NAMESPACE_DP' {
                        $NamespaceId = [BitConverter]::ToUInt32($DevicePathBytes, $FilePathEntryIndex + 4 + 0)
                        $NamespaceUuid = [Guid][byte[]] $DevicePathBytes[($FilePathEntryIndex + 4 + 4)..($FilePathEntryIndex + 4 + 19)]

                        $DeviceInfo = [PSCustomObject] @{
                            NamespaceId   = $NamespaceId
                            NamespaceUuid = $NamespaceUuid
                        }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }

                    default {
                        $DeviceSubType = $DevicePathBytes[$FilePathEntryIndex + 1].ToString('X2')
                        $DeviceInfo = [PSCustomObject] @{ RawDeviceBytes = $DataBytes }

                        [PSCustomObject] @{
                            Type       = $DevicePathType
                            SubType    = $DeviceSubType
                            DeviceInfo = $DeviceInfo
                        }
                    }
                }
            }

            'END_DEVICE_PATH_TYPE' { }

            default {
                # Until other subtypes are added, just supply the bytes.
                $DeviceSubType = $DevicePathBytes[$FilePathEntryIndex + 1].ToString('X2')

                [PSCustomObject] @{
                    Type    = $DevicePathType
                    SubType = $DeviceSubType
                    Length  = $Length
                    Data    = ($DataBytes | ForEach-Object { $_.ToString('X2') }) -join ':'
                }
            }
        }

        $FilePathEntryIndex = $FilePathEntryIndex + $Length
        $MoreToParse = $null -ne $DevicePathBytes[$FilePathEntryIndex]
    }

    return $FilePathList
}

function Get-TPMDeviceInfo {
    <#
.SYNOPSIS

Retrieves TPM information.

.DESCRIPTION

Get-TPMDeviceInfo retrieves limited TPM information.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.EXAMPLE

Get-TPMDeviceInfo
#>

    $TPM_DEVICE_INFO_Size = 16

    $DeviceInfo = New-Object -TypeName TPMBaseServices.TPM_DEVICE_INFO
    $Result = [TPMBaseServices.UnsafeNativeMethods]::Tbsi_GetDeviceInfo($TPM_DEVICE_INFO_Size, [Ref] $DeviceInfo)

    if ($Result -eq 0) {
        $DeviceInfo
    }
    else {
        Write-Error "Tbsi_GetDeviceInfo: $($TBSReturnCodes[$Result])"
    }
}

function Get-TCGLogContent {
    <#
.SYNOPSIS

Retrieves the contents of the Trusted Computing Group (TCG) log.

.DESCRIPTION

Get-TCGLogContent retrieves the contents of the TCG log (referred to as the "Windows Boot Configuration Log" (WBCL) by Microsoft). This log captures the various boot and runtime measurements used for device health attestation.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER LogType

Specifies the type of TCG log to retrieve. The following arguments are supported:

* SRTMCurrent (default): The log associated with PCRs 0-15 for the current session (boot or resume).
  * This option retrieves the contents of HKLM\SYSTEM\CurrentControlSet\Control\IntegrityServices\WBCL
* DRTMCurrent: The log associated with PCRs 17-22 for the current session (boot or resume).
  * This option retrieves the contents of HKLM\SYSTEM\CurrentControlSet\Control\IntegrityServices\WBCLDrtm
  * The presence of DRTM is validated with NtQuerySystemInformation - SYSTEM_BOOT_ENVIRONMENT_INFORMATION.DbgMeasuredLaunch
* SRTMBoot: The log associated with PCRs 0-15 for the most recent clean boot session.
  * This log is retrieved from the most current MeasuredBoot log from a clean boot state. For example, if the most recent log is C:\Windows\Logs\MeasuredBoot\0000000029-0000000003.log, This option will retrieve C:\Windows\Logs\MeasuredBoot\0000000029-0000000000.log (indicating the first MeasuredBoot log taken from a clean boot state).
* SRTMResume: The log associated with PCRs 0-15 for the most recent resume from hibernation.
  * This log is retrieved from the most current MeasuredBoot log taken immediately after the clean state boot log. For example, if the clean boot log is C:\Windows\Logs\MeasuredBoot\0000000029-0000000000.log, this options will retrieve C:\Windows\Logs\MeasuredBoot\0000000029-0000000001.log.

.EXAMPLE

Get-TCGLogContent

Retrieves the TCG log bytes associated with PCRs 0-15 for the current session (boot or resume).

.EXAMPLE

Get-TCGLogContent -LogType SRTMBoot

Retrieves the TCG log bytes associated with PCRs 0-15 for the most recent clean boot session.

.OUTPUTS

System.Byte[]

Outputs a byte array consisting of a raw TCG log. Supply the byte array to ConvertTo-TCGEventLog to parse the contents of the log.
#>

    [OutputType([Byte[]])]
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [String]
        [ValidateSet('SRTMCurrent', 'DRTMCurrent', 'SRTMBoot', 'SRTMResume')]
        $LogType = 'SRTMCurrent'
    )

    switch ($LogType) {
        'SRTMCurrent' { $LogTypeEnumVal = [TPMBaseServices.TBS_TCGLOG]::TBS_TCGLOG_SRTM_CURRENT }
        'DRTMCurrent' { $LogTypeEnumVal = [TPMBaseServices.TBS_TCGLOG]::TBS_TCGLOG_DRTM_CURRENT }
        'SRTMBoot' { $LogTypeEnumVal = [TPMBaseServices.TBS_TCGLOG]::TBS_TCGLOG_SRTM_BOOT }
        'SRTMResume' { $LogTypeEnumVal = [TPMBaseServices.TBS_TCGLOG]::TBS_TCGLOG_SRTM_RESUME }
    }

    $TCGLogSize = 0

    # Supply an empty buffer so that the size of the buffer will be returned.
    $Result = [TPMBaseServices.UnsafeNativeMethods]::Tbsi_Get_TCG_Log_Ex($LogTypeEnumVal, [IntPtr]::Zero, [Ref] $TCGLogSize)

    if ($Result -ne 0) {
        Write-Error "Tbsi_Get_TCG_Log_Ex: $($TBSReturnCodes[$Result])"

        return
    }

    if ($TCGLogSize) {
        Write-Verbose "TCG log size: 0x$($TCGLogSize.ToString('X8'))"
        $TCGLogBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($TCGLogSize)

        # Initialize the buffer to zero. AllocHGlobal won't initialize memory nor will Tbsi_Get_TCG_Log_Ex.
        for ($i = 0; $i -lt $TCGLogSize; $i++) {
            [Runtime.InteropServices.Marshal]::WriteByte($TCGLogBuffer, $i, 0)
        }

        $TCGLogBytes = New-Object -TypeName Byte[]($TCGLogSize)

        # Read the TCG log buffer.
        $Result = [TPMBaseServices.UnsafeNativeMethods]::Tbsi_Get_TCG_Log_Ex($LogTypeEnumVal, $TCGLogBuffer, [Ref] $TCGLogSize)

        if ($Result -ne 0) {
            Write-Error "Tbsi_Get_TCG_Log_Ex: $($TBSReturnCodes[$Result])"

            # Free the unmanaged memory
            [Runtime.InteropServices.Marshal]::FreeHGlobal($TCGLogBuffer)

            return
        }

        # Copy the buffer to the byte array
        [Runtime.InteropServices.Marshal]::Copy($TCGLogBuffer, $TCGLogBytes, 0, $TCGLogSize)

        # Free the unmanaged memory
        [Runtime.InteropServices.Marshal]::FreeHGlobal($TCGLogBuffer)
    }

    $TCGLogBytes
}

filter ConvertTo-TCGEventLog {
    <#
.SYNOPSIS

Parses a Trusted Computing Group (TCG) log.

.DESCRIPTION

ConvertTo-TCGEventLog parses one or more TCG logs (referred to as the "Windows Boot Configuration Log" (WBCL) by Microsoft). This log captures the various boot and runtime measurements used for device health attestation. ConvertTo-TCGEventLog will parse the log as a byte array or from one or more log files on disk.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER LogBytes

Specifies an array of bytes consisting of a raw TCG log.

.PARAMETER LogPath

Specifies the path to one or more TCG log files. On Windows 10 with TPM enabled, these logs are located at %windir%\Logs\MeasuredBoot by default. Optionally, you can specify an alternate TCG log path with HKLM\System\CurrentControlSet\services\TPM\WBCLPath (REG_EXPAND_SZ).

.PARAMETER

Specifies that any object that return a signature object should return an X509Certificate object. If this switch is not specified, X509Certificate2 objects will be returned. This switch is present in order to reduce the amount of data in JSON output.

.EXAMPLE

$TCGLogBytes = Get-TCGLogContent -LogType SRTMCurrent
$TCGLog = ConvertTo-TCGEventLog -LogBytes $TCGLogBytes

.EXAMPLE

ls C:\Windows\Logs\MeasuredBoot\*.log | ConvertTo-TCGEventLog

.EXAMPLE

ConvertTo-TCGEventLog -LogPath C:\Windows\Logs\MeasuredBoot\0000000001-0000000000.log

.EXAMPLE

ConvertTo-TCGEventLog -LogBytes (Get-TCGLogContent -LogType SRTMBoot) -MinimizedX509CertInfo | ConvertTo-Json -Depth 8 | Out-File TCGlog.json

Using the -MinimizedX509CertInfo so that JSON output is not as verbose.

.INPUTS

System.String

Accepts one or more TCG log file paths.

.OUTPUTS

PSCustomObject

Outputs a parsed TCG log.
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Bytes')]
        [Byte[]]
        $LogBytes,

        [Parameter(Mandatory, ParameterSetName = 'LogFile', ValueFromPipelineByPropertyName)]
        [String]
        [Alias('FullName')]
        [ValidateNotNullOrEmpty()]
        $LogPath,

        [Switch]
        $MinimizedX509CertInfo,

        [string]
        $DbxInfoPath = "$PSScriptRoot/dbx_info.csv",

        [switch]
        $GatherSBCP
    )

    $DbxInfo = $null
    if (![string]::IsNullOrEmpty($DbxInfoPath)) {
        $DbxInfo = @{}
        Import-Csv -LiteralPath $DbxInfoPath | ForEach-Object {
            $DbxInfo[$_."PE256 Authenticode"] = $_
        }
    }

    $LogFullPath = $null
    # The header should be at least this long in order to proceed with parsing.
    $MinimumHeaderLength = 65

    if ($LogBytes) {
        $TCGLogBytes = $LogBytes

        if ($TCGLogBytes.Count -lt $MinimumHeaderLength) {
            Write-Error "The supplied byte array is not of sufficient size to be a TCG log. It must be at least $MinimumHeaderLength bytes in length. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
            return
        }
    }
    else {
        # -LogPath was specified
        $LogFullPath = (Resolve-Path $LogPath).Path
        $TCGLogBytes = [IO.File]::ReadAllBytes($LogFullPath)

        if ($TCGLogBytes.Count -lt $MinimumHeaderLength) {
            Write-Error "$LogFullPath is not of sufficient size to be a TCG log. It must be at least $MinimumHeaderLength bytes in length. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
            return
        }
    }

    try {
        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(, $TCGLogBytes)
        $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream, ([Text.Encoding]::Unicode)
    }
    catch {
        throw $_
        return
    }

    $PCRIndex = $BinaryReader.ReadUInt32()

    if ($PCRIndex -ne 0) {
        Write-Error "TCG_PCR_EVENT.PCRIndex expected value: 0. Actual value: $PCRIndex. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
        $BinaryReader.Close()
        return
    }

    $EventType = $EventTypeMapping[$BinaryReader.ReadUInt32()]

    if ($EventType -ne 'EV_NO_ACTION') {
        Write-Error "TCG_PCR_EVENT.EventType expected value: EV_NO_ACTION. Actual value: $EventType. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
        $BinaryReader.Close()
        return
    }

    $Digest = $BinaryReader.ReadBytes(20)
    $DigestString = [BitConverter]::ToString($Digest).Replace('-', '')

    if ($DigestString -ne '0000000000000000000000000000000000000000') {
        Write-Error "TCG_PCR_EVENT.Digest expected value: 0000000000000000000000000000000000000000. Actual value: $DigestString. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
        $BinaryReader.Close()
        return
    }

    $EventSize = $BinaryReader.ReadUInt32()

    # Read the TCG_EfiSpecIdEventStruct instance contents
    $Signature = [Text.Encoding]::ASCII.GetString($BinaryReader.ReadBytes(16)).TrimEnd(@(0, 0))

    if ($Signature -ne 'Spec ID Event03') {
        Write-Error "TCG_PCR_EVENT.Event.Signature expected value: Spec ID Event03. Actual value: $Signature. It is likely that the data supplied to ConvertTo-TCGEventLog is not a TCG log."
        $BinaryReader.Close()
        return
    }

    # At this point, there is a very reasonable confidence that this is a well-formed TCG log.

    $PlatformClass = $BinaryReader.ReadUInt32()
    $SpecVersionMinor = $BinaryReader.ReadByte()
    $SpecVersionMajor = $BinaryReader.ReadByte()
    $SpecErrata = $BinaryReader.ReadByte()
    $UintNSize = $BinaryReader.ReadByte()
    $NumberOfAlgorithms = $BinaryReader.ReadUInt32()

    $DigestSizes = New-Object -TypeName PSObject[]($NumberOfAlgorithms)

    for ($i = 0; $i -lt $NumberOfAlgorithms; $i++) {
        $DigestSizes[$i] = New-Object -TypeName PSObject -Property @{
            HashAlg    = $DigestAlgorithmMapping[$BinaryReader.ReadUInt16()]
            DigestSize = $BinaryReader.ReadUInt16()
        }
    }

    $VendorInfoSize = $BinaryReader.ReadByte()
    $VendorInfo = $BinaryReader.ReadBytes($vendorInfoSize)

    # Described here: https://msdn.microsoft.com/en-us/library/windows/desktop/bb530712(v=vs.85).aspx
    $TCG_EfiSpecIdEventStruct = [PSCustomObject] @{
        PSTypeName         = 'TCGEfiSpecIdEvent'
        Signature          = $Signature
        PlatformClass      = $PlatformClass
        SpecVersionMinor   = $SpecVersionMinor
        SpecVersionMajor   = $SpecVersionMajor
        SpecErrata         = $SpecErrata
        UintNSize          = $UintNSize
        NumberOfAlgorithms = $NumberOfAlgorithms
        DigestSizes        = $DigestSizes
        VendorInfoSize     = $VendorInfoSize
        VendorInfo         = $VendorInfo
    }

    $TCGHeader = [PSCustomObject] @{
        PSTypeName = 'TCGPCREvent'
        PCR        = $PCRIndex
        EventType  = $EventType
        Digest     = $DigestString
        Event      = $TCG_EfiSpecIdEventStruct
    }

    # Loop through all the remaining measurements, parsing each TCG_PCR_EVENT2 struct along the way
    $Events = while ($BinaryReader.PeekChar() -ne -1) {
        $PCRIndex = $BinaryReader.ReadInt32()

        $EventTypeVal = $BinaryReader.ReadUInt32()
        $EventType = $EventTypeMapping[$EventTypeVal]
        if (-not $EventType) { $EventType = $EventTypeVal.ToString('X8') }

        # Multiple digests can be calculated/stored but in plractice, you will likely only over see one digest.
        $DigestValuesCount = $BinaryReader.ReadUInt32()

        if ($DigestValuesCount -eq 1) {
            $HashAlg = $DigestAlgorithmMapping[$BinaryReader.ReadUInt16()]
            $DigestSize = $DigestSizeMapping[$HashAlg]

            $Digests = [BitConverter]::ToString($BinaryReader.ReadBytes($DigestSize)).Replace('-', '')
        }
        else {
            $Digests = New-Object -TypeName PSObject[]($DigestValuesCount)

            for ($i = 0; $i -lt $DigestValuesCount; $i++) {
                $HashAlg = $DigestAlgorithmMapping[$BinaryReader.ReadUInt16()]
                $DigestSize = $DigestSizeMapping[$HashAlg]

                $Digests[$i] = [BitConverter]::ToString($BinaryReader.ReadBytes($DigestSize)).Replace('-', '')
            }
        }


        $EventSize = $BinaryReader.ReadUInt32()

        $ThisEvent = $null

        # Parse specific event types. Event types that are not explicitly parsed will return a byte array of the contents.
        switch ($EventType) {
            'EV_S_CRTM_CONTENTS' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)
                $ThisEvent = [Text.Encoding]::ASCII.GetString($EventBytes).TrimEnd(@(0))
            }

            'EV_POST_CODE' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)
                $ThisEvent = [Text.Encoding]::ASCII.GetString($EventBytes).TrimEnd(@(0))
            }

            'EV_EFI_PLATFORM_FIRMWARE_BLOB' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)
                $BlobBase = [BitConverter]::ToUInt64($EventBytes, 0)
                $BlobLength = [BitConverter]::ToUInt64($EventBytes, 8)

                # Chipsec can dump this for validation:
                # chipsec_util.py mem read [BlobBase] [BlobLength] firmwareblob.bin
                # What's dumped will likely be a firmware volume. I use UEFITool.exe to extract contents.

                $ThisEvent = [PSCustomObject] @{
                    PSTypeName = 'TCGUEFIPlatformFirmwareBlob'
                    BlobBase   = $BlobBase
                    BlobLength = $BlobLength
                }
            }

            'EV_EVENT_TAG' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                # These will be Windows-specific data structures
                $ThisEvent = Get-SIPAEventData -SIPAEventBytes $EventBytes
            }

            'EV_NO_ACTION' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                if ($PCRIndex -eq -1) {
                    # Extact TrustPoint information - used for log attestation
                    $ThisEvent = Get-SIPAEventData -SIPAEventBytes $EventBytes
                }
                else {
                    $ThisEvent = $EventBytes
                }
            }

            'EV_EFI_GPT_EVENT' {
                # This will consist of a UEFI_GPT_DATA structure.

                # EFI_TABLE_HEADER: Start
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                $GPTMemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(, $EventBytes)
                $GPTBinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $GPTMemoryStream, ([Text.Encoding]::Unicode)

                $Signature = [Text.Encoding]::ASCII.GetString($GPTBinaryReader.ReadBytes(8)).TrimEnd(@(0))
                $SpecMinor = [Int32] $GPTBinaryReader.ReadInt16()
                $SpecMajor = [Int32] $GPTBinaryReader.ReadInt16()

                $Revision = New-Object -TypeName Version -ArgumentList @($SpecMajor, $SpecMinor, 0, 0)

                $null = $GPTBinaryReader.ReadUInt32() # HeaderSize
                $CRC32 = $GPTBinaryReader.ReadUInt32()
                $null = $GPTBinaryReader.ReadUInt32() # Reserved

                $TableHeader = [PSCustomObject] @{
                    Signature = $Signature
                    Revision  = $Revision
                    CRC32     = $CRC32
                }
                # EFI_TABLE_HEADER: End

                # EFI_PARTITION_TABLE_HEADER: Start
                $MyLBA = $GPTBinaryReader.ReadUInt64()
                $AlternateLBA = $GPTBinaryReader.ReadUInt64()
                $FirstUsableLBA = $GPTBinaryReader.ReadUInt64()
                $LastUsableLBA = $GPTBinaryReader.ReadUInt64()

                $DiskGUID = [Guid][Byte[]] $GPTBinaryReader.ReadBytes(16)

                $PartitionEntryLBA = $GPTBinaryReader.ReadUInt64()
                $NumberOfPartitionEntries = $GPTBinaryReader.ReadUInt32()
                $SizeOfPartitionEntry = $GPTBinaryReader.ReadUInt32()
                $PartitionEntryArrayCRC32 = $GPTBinaryReader.ReadUInt32()
                # EFI_PARTITION_TABLE_HEADER: End

                $EFIPartitionHeader = [PSCustomObject] @{
                    Header                   = $TableHeader
                    MyLBA                    = $MyLBA
                    AlternateLBA             = $AlternateLBA
                    FirstUsableLBA           = $FirstUsableLBA
                    LastUsableLBA            = $LastUsableLBA
                    DiskGUID                 = $DiskGUID
                    PartitionEntryLBA        = $PartitionEntryLBA
                    NumberOfPartitionEntries = $NumberOfPartitionEntries
                    SizeOfPartitionEntry     = $SizeOfPartitionEntry
                    PartitionEntryArrayCRC32 = $PartitionEntryArrayCRC32
                }

                $NumberOfPartitions = $GPTBinaryReader.ReadUInt64()

                $Partitions = New-Object PSObject[]($NumberOfPartitions)

                for ($i = 0; $i -lt $NumberOfPartitions; $i++) {
                    $PartitionTypeGUID = [Guid][Byte[]] $GPTBinaryReader.ReadBytes(16)
                    $PartitionTypeName = $PartitionGUIDMapping[$PartitionTypeGUID.Guid]
                    $UniquePartitionGUID = [Guid][Byte[]] $GPTBinaryReader.ReadBytes(16)
                    $StartingLBA = $GPTBinaryReader.ReadUInt64()
                    $EndingLBA = $GPTBinaryReader.ReadUInt64()
                    $Attributes = $GPTBinaryReader.ReadUInt64()
                    $PartitionName = [Text.Encoding]::Unicode.GetString($GPTBinaryReader.ReadBytes(72)).TrimEnd(@(0))

                    $Partitions[$i] = [PSCustomObject] @{
                        PartitionTypeGUID   = $PartitionTypeGUID
                        PartitionTypeName   = $PartitionTypeName
                        UniquePartitionGUID = $UniquePartitionGUID
                        StartingLBA         = $StartingLBA
                        EndingLBA           = $EndingLBA
                        Attributes          = $Attributes
                        PartitionName       = $PartitionName
                    }
                }

                $ThisEvent = [PSCustomObject] @{
                    EfiPartitionHeader = $EfiPartitionHeader
                    NumberOfPartitions = $NumberOfPartitions
                    Partitions         = $Partitions
                }

                $GPTBinaryReader.Close()
            }

            'EV_SEPARATOR' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                if ($PCRIndex -gt 11) {
                    $ThisEvent = [Text.Encoding]::ASCII.GetString($EventBytes)
                }
                else {
                    $ThisEvent = ($EventBytes | ForEach-Object { $_.ToString('X2') }) -join ':'
                }
            }

            'EV_EFI_VARIABLE_AUTHORITY' {
                $VariableName = [Guid] $BinaryReader.ReadBytes(16)
                $UnicodeNameLength = $BinaryReader.ReadUInt64()
                $VariableDataLength = $BinaryReader.ReadUInt64()
                $UnicodeName = [Text.Encoding]::Unicode.GetString($BinaryReader.ReadBytes($UnicodeNameLength * 2)).TrimEnd(@(0))

                [Byte[]] $SignatureDataBytes = $BinaryReader.ReadBytes($VariableDataLength)

                if (@('PK', 'KEK', 'db', 'dbx') -contains $UnicodeName) {
                    # A EFI_SIGNATURE_DATA instance
                    # "The EFI_VARIABLE_DATA.VariableData value shall be the EFI_SIGNATURE_DATA value from
                    # the EFI_SIGNATURE_LIST that contained the authority that was used to validate the image
                    # and the EFI_VARIABLE_DATA.VariableName shall be set to EFI_IMAGE_SECURITY_DATABASE_GUID.
                    # The EFI_VARIABLE_DATA.UnicodeName shall be set to the value of EFI_IMAGE_SECURITY_DATABASE."
                    $SignatureOwner = [Guid][Byte[]] $SignatureDataBytes[0..15]
                    $SignatureBytes = $SignatureDataBytes[16..($SignatureDataBytes.Count - 1)]

                    $SignatureData = ConvertTo-CertificateInfo -CertificateData $SignatureBytes -Details:(!$MinimizedX509CertInfo)

                    $VariableData = [PSCustomObject] @{
                        SignatureOwner = $SignatureOwner
                        SignatureData  = $SignatureData
                    }
                }
                else {
                    # Just return a byte array for unknown/new UEFI variables
                    $VariableData = $SignatureDataBytes
                }

                $ThisEvent = [PSCustomObject] @{
                    PSTypeName   = 'TCGUEFIVariable'
                    VariableGUID = $VariableName
                    VariableName = $UnicodeName
                    VariableData = $VariableData
                }
            }

            'EV_EFI_VARIABLE_DRIVER_CONFIG' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                $VarMemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(, $EventBytes)
                $VarBinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $VarMemoryStream, ([Text.Encoding]::Unicode)

                $VariableName = [Guid] $VarBinaryReader.ReadBytes(16)

                # To-do: These lengths are dependant upon the platform architecture. Currently, I'm only considering 64-bit platforms
                $UnicodeNameLength = $VarBinaryReader.ReadUInt64()
                $VariableDataLength = $VarBinaryReader.ReadUInt64()
                $UnicodeName = [Text.Encoding]::Unicode.GetString($VarBinaryReader.ReadBytes($UnicodeNameLength * 2)).TrimEnd(@(0))

                if (@('PK', 'KEK', 'db', 'dbx') -contains $UnicodeName) {
                    # Parse out the EFI_SIGNATURE_LIST structs

                    $SignatureTypeMapping = @{
                        'C1C41626-504C-4092-ACA9-41F936934328' = 'EFI_CERT_SHA256_GUID' # Most often used for dbx
                        'A5C059A1-94E4-4AA7-87B5-AB155C2BF072' = 'EFI_CERT_X509_GUID'   # Most often used for db
                    }

                    while ($VarBinaryReader.PeekChar() -ne -1) {
                        $SignatureType = $SignatureTypeMapping[([Guid][Byte[]] $VarBinaryReader.ReadBytes(16)).Guid]
                        $SignatureListSize = $VarBinaryReader.ReadUInt32()
                        $SignatureHeaderSize = $VarBinaryReader.ReadUInt32()
                        $SignatureSize = $VarBinaryReader.ReadUInt32()

                        $null = $VarBinaryReader.ReadBytes($SignatureHeaderSize) # SignatureHeader

                        # 0x1C is the size of the EFI_SIGNATURE_LIST header
                        $SignatureCount = ($SignatureListSize - 0x1C) / $SignatureSize

                        $Signature = 1..$SignatureCount | ForEach-Object {
                            $SignatureDataBytes = $VarBinaryReader.ReadBytes($SignatureSize)

                            $SignatureOwner = [Guid][Byte[]] $SignatureDataBytes[0..15]

                            switch ($SignatureType) {
                                'EFI_CERT_SHA256_GUID' {
                                    $Hash = ([Byte[]] $SignatureDataBytes[0x10..0x2F] | ForEach-Object { $_.ToString('X2') }) -join ''
                                    $HashDbxInfo = $null
                                    if ($UnicodeName -eq 'dbx' -and $null -ne $DbxInfo) {
                                        $HashDbxInfo = $DbxInfo[$Hash]
                                    }
                                    $SignatureData = @{
                                        Hash = $Hash
                                    }
                                    if ($null -ne $HashDbxInfo) {
                                        $SignatureData["dbx_info"] = $HashDbxInfo
                                    }
                                }

                                'EFI_CERT_X509_GUID' {
                                    $SignatureData = ConvertTo-CertificateInfo -CertificateData ([Byte[]] $SignatureDataBytes[16..($SignatureDataBytes.Count - 1)]) -Details:(!$MinimizedX509CertInfo)
                                }
                            }

                            [PSCustomObject] @{
                                PSTypeName     = 'EFI.SignatureData'
                                SignatureOwner = $SignatureOwner
                                SignatureData  = $SignatureData
                            }
                        }

                        $VariableData = [PSCustomObject] @{
                            SignatureType = $SignatureType
                            Signature     = $Signature
                        }
                    }
                }
                else {
                    $VariableData = $VarBinaryReader.ReadBytes($VariableDataLength)
                }

                $VarBinaryReader.Close()

                $ThisEvent = [PSCustomObject] @{
                    PSTypeName   = 'TCGUEFIVariable'
                    VariableGUID = $VariableName
                    VariableName = $UnicodeName
                    VariableData = $VariableData
                }
            }

            'EV_EFI_BOOT_SERVICES_APPLICATION' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)

                $ImageLocationInMemory = [BitConverter]::ToUInt64($EventBytes, 0)
                $ImageLengthInMemory = [BitConverter]::ToUInt64($EventBytes, 8)
                $ImageLinkTimeAddress = [BitConverter]::ToUInt64($EventBytes, 16)
                $LengthOfDevicePath = [BitConverter]::ToUInt64($EventBytes, 24)

                $FilePathList = $null

                # Parse all the file list entries
                if ($LengthOfDevicePath -gt 0) {
                    $DevicePathBytes = $EventBytes[32..(32 + $LengthOfDevicePath - 1)]
                    $FilePathList = Get-EfiDevicePathProtocol -DevicePathBytes $DevicePathBytes
                }

                $ThisEvent = [PSCustomObject] @{
                    ImageLocationInMemory = $ImageLocationInMemory
                    ImageLengthInMemory   = $ImageLengthInMemory
                    ImageLinkTimeAddress  = $ImageLinkTimeAddress
                    DevicePath            = $FilePathList
                }
            }

            'EV_EFI_ACTION' {
                $EventBytes = $BinaryReader.ReadBytes($EventSize)
                $ThisEvent = [Text.Encoding]::ASCII.GetString($EventBytes).TrimEnd(@(0))
            }

            'EV_EFI_VARIABLE_BOOT' {
                $VariableName = [Guid] $BinaryReader.ReadBytes(16)

                $UnicodeNameLength = $BinaryReader.ReadUInt64()
                $VariableDataLength = $BinaryReader.ReadUInt64()
                $UnicodeName = [Text.Encoding]::Unicode.GetString($BinaryReader.ReadBytes($UnicodeNameLength * 2)).TrimEnd(@(0))

                if ($UnicodeName -eq 'BootOrder') {
                    $VariableData = 1..($VariableDataLength / 2) | ForEach-Object { $BinaryReader.ReadUInt16().ToString('X4') }
                }
                elseif ($UnicodeName -match '^Boot[0-9A-F]{4}$') {
                    $VariableDataBytes = $BinaryReader.ReadBytes($VariableDataLength)

                    $Attributes = [BitConverter]::ToUInt32($VariableDataBytes, 0)
                    $FilePathListLength = [BitConverter]::ToUInt16($VariableDataBytes, 4)

                    $Index = 6

                    $DescriptionChars = do {
                        $CharVal = [BitConverter]::ToUInt16($VariableDataBytes, $index)
                        [Char] $CharVal

                        $Index += 2
                    } while ($CharVal -ne 0)

                    [String] $Description = $DescriptionChars -join ''

                    $FilePathListEndIndex = $Index + $FilePathListLength - 1
                    # This will be of type: EFI_DEVICE_PATH_PROTOCOL
                    [Byte[]] $FilePathListBytes = $VariableDataBytes[$Index..$FilePathListEndIndex]
                    $FilePathList = Get-EfiDevicePathProtocol -DevicePathBytes $FilePathListBytes

                    $OptionalData = $null

                    # The remaining bytes in the load option descriptor are a binary data buffer that is passed to the loaded image.
                    # If the field is zero bytes long, a NULL pointer is passed to the loaded image. The number of bytes in OptionalData
                    # can be computed by subtracting the starting offset of OptionalData from total size in bytes of the EFI_LOAD_OPTION.
                    if (($VariableDataBytes.Count - ($FilePathListEndIndex + 1)) -gt 0) { $OptionalData = $VariableDataBytes[($FilePathListEndIndex + 1)..($VariableDataBytes.Count - 1)] }

                    if ($OptionalData) { $OptionalData = ($OptionalData | ForEach-Object { $_.ToString('X2') }) -join ':' }

                    $VariableData = [PSCustomObject] @{
                        Attributes         = $Attributes
                        FilePathListLength = $FilePathListLength
                        Description        = $Description.TrimEnd(@(0))
                        FilePathList       = $FilePathList
                        OptionalData       = $OptionalData
                    }
                }
                else {
                    $VariableData = $BinaryReader.ReadBytes($VariableDataLength)
                }

                $ThisEvent = [PSCustomObject] @{
                    PSTypeName   = 'TCGUEFIVariable'
                    VariableGUID = $VariableName
                    VariableName = $UnicodeName
                    VariableData = $VariableData
                }
            }

            'EV_EFI_HANDOFF_TABLES' {
                $NumberOfTables = $BinaryReader.ReadUInt64()
                $Tables = [System.Collections.Generic.List[PSCustomObject]]::new()
                for ($i = 0; $i -lt $NumberOfTables; $i++) {
                    $Table = [PSCustomObject] @{
                        VendorGUID  = [Guid][Byte[]] $BinaryReader.ReadBytes(16)
                        VendorTable = $BinaryReader.ReadUInt64()
                    }
                    $Tables.Add($Table)
                }

                $ThisEvent = [PSCustomObject]@{
                    Tables = $Tables
                }
            }

            'EV_EFI_HANDOFF_TABLES2' {
                $TableDescriptionLength = $BinaryReader.ReadByte()
                $TableDescription = [Text.Encoding]::ASCII.GetString($BinaryReader.ReadBytes($TableDescriptionLength)).TrimEnd(@(0))
                $NumberOfTables = $BinaryReader.ReadUInt64()
                for ($i = 0; $i -lt $NumberOfTables; $i++) {
                    $Table = [PSCustomObject] @{
                        VendorGUID  = [Guid][Byte[]] $BinaryReader.ReadBytes(16)
                        VendorTable = $BinaryReader.ReadUInt64()
                    }
                    $Tables.Add($Table)
                }

                $ThisEvent = [PSCustomObject]@{
                    TableDescription = $TableDescription;
                    Tables           = $Tables
                }
            }

            default {
                $ThisEvent = ($BinaryReader.ReadBytes($EventSize) | ForEach-Object { $_.ToString('X2') }) -join ':'
            }
        }

        [Ordered] @{
            PCR       = $PCRIndex
            EventType = $EventType
            Digest    = $Digests
            Event     = $ThisEvent
        }
    }

    $BinaryReader.Close()

    $PCRTemplate = [Ordered] @{
        PCR0        = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR1        = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR2        = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR3        = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR4        = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR5        = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR6        = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR7        = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR8        = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR9        = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR10       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR11       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR12       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR13       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR14       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR15       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR16       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR17       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR18       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR19       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR20       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR21       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR22       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCR23       = (New-Object 'System.Collections.Generic.List[PSObject]')
        PCRMinusOne = (New-Object 'System.Collections.Generic.List[PSObject]')
    }

    foreach ($PCRMeasurement in $Events) {
        if ($PCRMeasurement['PCR'] -eq -1) {
            $PCRMeasurement.Remove('PCR')
            $PCRTemplate['PCRMinusOne'].Add(([PSCustomObject] $PCRMeasurement))
        }
        else {
            $PCRNum = $PCRMeasurement['PCR']
            $PCRMeasurement.Remove('PCR')
            $PCRTemplate["PCR$($PCRNum)"].Add(([PSCustomObject] $PCRMeasurement))
        }
    }

    foreach ($Key in $PCRTemplate.GetEnumerator().Name) {
        if ($PCRTemplate[$Key].Count -eq 0) { $PCRTemplate[$Key] = $null }
        if ($PCRTemplate[$Key].Count -eq 1) { $PCRTemplate[$Key] = $PCRTemplate[$Key][0] }
    }

    $TCGEventLog = [PSCustomObject] @{
        PSTypeName = 'TCGLog'
        LogPath    = $LogFullPath
        Header     = $TCGHeader
        Events     = ([PSCustomObject] $PCRTemplate)
    }

    $TCGEventLog
}

Export-ModuleMember -Function Get-TCGLogContent, ConvertTo-TCGEventLog, Get-TPMDeviceInfo
