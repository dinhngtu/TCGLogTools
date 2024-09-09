## EV_POST_CODE event `ACPI DATA`

This event measures two ACPI tables: `SSDT` table with OEM ID "Tpm2Tabl" and `TPM2` tables.
These tables are patched after they are measured (see [here](https://github.com/tianocore/edk2/blob/edc6681206c1a8791981a2f911d2fb8b3d2f5768/SecurityPkg/Tcg/Tcg2Acpi/Tcg2Acpi.c#L660) and [here](https://github.com/tianocore/edk2/blob/edc6681206c1a8791981a2f911d2fb8b3d2f5768/SecurityPkg/Tcg/Tcg2Acpi/Tcg2Acpi.c#L777)).
So to verify these measurements we probably need to extract the original ACPI tables from firmware, rather than extracting the tables directly from a running system (using `acpidump` and the like).

## `MEDIA_PIWG_FW_VOL_DP\MEDIA_PIWG_FW_FILE_DP`

Look for the `MEDIA_PIWG_FW_FILE_DP` GUID in UEFITool, you should find a PE image section inside the referenced FW file.
The `EV_EFI_BOOT_SERVICES_APPLICATION` event hash corresponds to the Authenticode hash of that file.
