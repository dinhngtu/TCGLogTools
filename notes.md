## EV_POST_CODE event `ACPI DATA`

This event measures two ACPI tables: `SSDT` table with OEM ID "Tpm2Tabl" and `TPM2` tables.
These tables are patched after they are measured (see [here](https://github.com/tianocore/edk2/blob/edc6681206c1a8791981a2f911d2fb8b3d2f5768/SecurityPkg/Tcg/Tcg2Acpi/Tcg2Acpi.c#L660) and [here](https://github.com/tianocore/edk2/blob/edc6681206c1a8791981a2f911d2fb8b3d2f5768/SecurityPkg/Tcg/Tcg2Acpi/Tcg2Acpi.c#L777)).
So to verify these measurements we probably need to extract the original ACPI tables from firmware, rather than extracting the tables directly from a running system (using `acpidump` and the like).

## `MEDIA_PIWG_FW_VOL_DP\MEDIA_PIWG_FW_FILE_DP`

Look for the `MEDIA_PIWG_FW_FILE_DP` GUID in UEFITool, you should find a PE image section inside the referenced FW file.
The `EV_EFI_BOOT_SERVICES_APPLICATION` event hash corresponds to the Authenticode hash of that file.

## KB5025885 and CVE-2023-24932 mitigation

### PCR7 event indicating updated certificate

```json
{
  "PCR": 7,
>>"EventType": "EV_EFI_VARIABLE_DRIVER_CONFIG",
  "Event": {
    "VariableGUID": "d719b2cb-3d3a-4596-a3bc-dad00e67656f",
>>  "VariableName": "db",
    "VariableData": [
      ...,
      {
        "SignatureType": "EFI_CERT_X509_GUID",
        "Signature": {
          "SignatureOwner": "77fa9abd-0359-4d32-bd60-28f4e78f784b",
          "SignatureData": {
            "Thumbprint": "45A0FA32604773C82433C3B7D59E7466B3AC0C67",
            "Issuer": "CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
            "NotBefore": "2023-06-13T18:58:29.0000000Z",
            "NotAfter": "2035-06-13T19:08:29.0000000Z",
            "SerialNumber": "330000001A888B9800562284C100000000001A",
>>          "Subject": "CN=Windows UEFI CA 2023, O=Microsoft Corporation, C=US"
          }
        }
      }
    ]
  }
}
```

### PCR7/PCR4 events indicating that the system booted with the updated "Windows UEFI CA 2023"-signed Boot Manager

```json
{
  "PCR": 7,
>>"EventType": "EV_EFI_VARIABLE_AUTHORITY",
  "Event": {
    "VariableGUID": "d719b2cb-3d3a-4596-a3bc-dad00e67656f",
>>  "VariableName": "db",
    "VariableData": {
      "SignatureOwner": "77fa9abd-0359-4d32-bd60-28f4e78f784b",
      "SignatureData": {
        "Thumbprint": "45A0FA32604773C82433C3B7D59E7466B3AC0C67",
        "Issuer": "CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
        "NotBefore": "2023-06-13T18:58:29.0000000Z",
        "NotAfter": "2035-06-13T19:08:29.0000000Z",
        "SerialNumber": "330000001A888B9800562284C100000000001A",
>>      "Subject": "CN=Windows UEFI CA 2023, O=Microsoft Corporation, C=US"
      }
    }
  }
},
{
  "PCR": 4,
>>"EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
>>"Digest": "497DDE9B5EEAA3D97F464310BA8936501C45B43C180C2F25AE4918921170CBBB",
  "Event": {
    ...,
    "DevicePath": [
      ...,
      {
        "Type": "MEDIA_DEVICE_PATH",
        "SubType": "MEDIA_FILEPATH_DP",
        "DeviceInfo": {
>>        "PathName": "\\EFI\\Microsoft\\Boot\\bootmgfw.efi"
        }
      },
      {
        "Type": "END_DEVICE_PATH_TYPE",
        "SubType": "END_ENTIRE_DEVICE_PATH_SUBTYPE"
      }
    ]
  }
}
```

The Authenticode hash of the file in question should match with the recorded digest of the PCR4 event:

```
C:\>sigcheck -h S:\EFI\Microsoft\Boot\bootmgfw.efi

Sigcheck v2.90 - File version and signature viewer
Copyright (C) 2004-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

s:\efi\microsoft\boot\bootmgfw.efi:
        Verified:       Signed
        Signing date:   02:59 07/08/2024
        Publisher:      Microsoft Windows
        Company:        Microsoft Corporation
        Description:    Boot Manager
        Product:        Microsoft« Windows« Operating System
        Prod version:   10.0.26100.1041
        File version:   10.0.26100.1041 (WinBuild.160101.0800)
        MachineType:    64-bit
        MD5:    E21D021F208984BE03D4B4D21116CC70
        SHA1:   3B019721E670CD5A04AD292726662DFC57AB263A
        PESHA1: AFD39899F6B6D73522F11B6DC256DA3F2C5BFD70
>>      PE256:  497DDE9B5EEAA3D97F464310BA8936501C45B43C180C2F25AE4918921170CBBB
        SHA256: 784CF8AC98480838C04D3B67FED444BA33936C4D97E1D61C96624DDB0DDE6B56
        IMP:    n/a
```

### PCR7 event indicating successful revocation of vulnerable boot managers

```json
{
  "PCR": 7,
>>"EventType": "EV_EFI_VARIABLE_DRIVER_CONFIG",
  "Event": {
    "VariableGUID": "d719b2cb-3d3a-4596-a3bc-dad00e67656f",
>>  "VariableName": "dbx",
    "VariableData": [
      ...,
      {
        "SignatureType": "EFI_CERT_X509_GUID",
        "Signature": {
          "SignatureOwner": "77fa9abd-0359-4d32-bd60-28f4e78f784b",
          "SignatureData": {
            "Thumbprint": "580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D",
            "Issuer": "CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
            "NotBefore": "2011-10-19T18:41:42.0000000Z",
            "NotAfter": "2026-10-19T18:51:42.0000000Z",
            "SerialNumber": "61077656000000000008",
>>          "Subject": "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
          }
        }
      }
    ]
  }
}
```

Note that [EventType isn’t part of the Digest and can be freely modified by an attacker](https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md).

## WindowsBootChainSvn rollback detection

The EFI variable `77fa9abd-0359-4d32-bd60-28f4e78f784b WindowsBootChainSvn` (NV, BS) contains the current SVN:

```
0000000: 0100 0000                                ....
```

Setting it to an unacceptable value (e.g. `05 00 00 00`) will not cause a boot failure but will log an error in SIPA:

```json
{
  "SIPAEventType": "SVNChainStatus",
  "SIPAEventData": 3221225506 // STATUS_ACCESS_DENIED
},
```
