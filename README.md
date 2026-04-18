[![Download Latest Release](https://img.shields.io/github/v/release/UniFy-Endpoint/Secure-Boot-Certificate?label=Download%20Latest&style=for-the-badge&logo=github)](https://github.com/UniFy-Endpoint/Secure-Boot-Certificate/releases/latest)

# Secure Boot Windows UEFI CA 2023 — Intune Management Scripts

Automates detection and remediation of the **Windows UEFI CA 2023** Secure Boot certificate update on Windows devices. Designed for Microsoft Intune but fully usable as local administrator scripts.

---

## Scripts in this Package

| Script | Purpose | Intune Deployment |
|---|---|---|
| `Manage-SecureBoot-Certificate-Update.ps1` | Unified single-file detect + remediate | Platform Script |
| `Detect-SecureBoot-Certificate-Update.ps1` | Detection only (exit 0/1) | Proactive Remediation — Detection |
| `Remediate-SecureBoot-Certificate-Update.ps1` | Remediation only (exit 0/1) | Proactive Remediation — Remediation |

---

## Feature Comparison

| Feature | Manage (Unified) | Detect | Remediate |
|---|:---:|:---:|:---:|
| Binary X.509 parse of Secure Boot DB | Yes | Yes | Yes |
| Full registry state machine (7 states) | Yes | Yes | Yes |
| OS patch level check (Win10/11 table) | Yes | Yes | Yes |
| Firmware type detection (UEFI vs BIOS) | Yes | Yes | Yes |
| TPM presence, version, event log | Yes | Yes | Yes |
| Hardware make/model, VM detection | Yes | Yes | Yes |
| Disk partition style (GPT/MBR) | Yes | Yes | Yes |
| MDM Settings Catalog policy detection | Yes | Yes | Yes |
| MDM conflict guard (no registry write conflict) | Yes | No | Yes |
| Sets `AvailableUpdates` registry trigger | Yes (Auto mode) | No | Yes |
| Starts `Secure-Boot-Update` scheduled task | Yes (Auto mode) | No | Yes |
| `-WhatIf` support (ShouldProcess) | Yes | No | Yes |
| Auto mode from filename | Yes | N/A | N/A |
| Intune Proactive Remediation exit codes | Partial | Yes | Yes |
| Log file written to IME Logs folder | Yes | Yes | Yes |
| Log rotation (3 runs kept on disk) | Yes | Yes | Yes |
| Pending reboot detection (CBS + Windows Update) | Yes | Yes | Yes |
| Windows Application Event Log entry per run | Yes | Yes | Yes |
| Secure Boot firmware event monitoring (1795/1796) | Yes | Yes | Yes |
| UEFICA2023ErrorEvent System log cross-reference | Yes | Yes | Yes |
| AvailableUpdatesPolicy monitoring (GPO trigger) | Yes | Yes | Yes |
| VM type-specific warnings (Hyper-V, VMware) | Yes | N/A | Yes |
| Mutual exclusion guard (-DetectOnly / -RemediateOnly) | Yes | N/A | N/A |

---

## How It Works

### Detection Logic

Two independent checks are performed. Either one passing is sufficient for compliance:

1. **Binary X.509 certificate parse** — Reads the raw UEFI Secure Boot signature database (`db`) and walks the EFI Signature List binary format entry by entry, loading each X.509 certificate and checking for `Windows UEFI CA 2023` in the subject. This is the most reliable indicator: the certificate is physically present in firmware.

2. **Registry state machine** — If the certificate is not yet visible in the DB, the scripts evaluate the Windows update process state via `UEFICA2023Status`:

   | `UEFICA2023Status` | Condition | Result |
   |---|---|---|
   | *(not checked)* | Certificate found in Secure Boot DB | **Compliant** |
   | `Updated` | `Capable = 0x2` and no error | **Compliant** |
   | `Updated` | `Capable ≠ 0x2` or error present | **Non-Compliant** — investigate |
   | `InProgress` | `AvailableUpdates` has bit `0x4100` | **Compliant** — reboot pending |
   | `InProgress` | Other | **Compliant** — update in progress |
   | `InProgress` | Bit `0x0004` set + error present | **Compliant** (investigate) — KEK blocked; apply OEM BIOS update |
   | `NotStarted` | Trigger already set to `0x5944` | **Compliant** — waiting for task |
   | `NotStarted` | Trigger not set | **Non-Compliant** — needs remediation |
   | *(not set)* | Key absent | **Non-Compliant** — update not started |
   | `Failed` | Error state | **Non-Compliant** — check `UEFICA2023Error`; OEM BIOS update may be required |
   | Any other value | — | **Non-Compliant** — unknown state |

### Remediation Logic

When non-compliant, the remediation script applies **two steps** using only Windows' own built-in update mechanism:

1. Sets `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates = 0x5944`
   - This bitmask enables all relevant update components (DB, KEK, DBX, BootMgr, SVN, SBAT, Option ROM, UEFI CA 2023, post-reboot stage).
   - Idempotent: skipped if the value is already set to the target.
2. Starts the Windows scheduled task `\Microsoft\Windows\PI\Secure-Boot-Update`
   - This triggers Windows' own certificate deployment process.
   - A system reboot is typically required to complete the deployment.

> **No certificates are ever directly injected or removed.** The scripts only set the trigger for Windows' built-in mechanism.

### Safety Guards

The remediation script will **skip all changes** (exit 0 with a warning) if:

- Secure Boot is disabled or not supported
- Device is running legacy BIOS (non-UEFI)
- Device is a virtual machine (Hyper-V, VMware, VirtualBox, QEMU, Parallels)
- Intune Settings Catalog MDM policies are managing the update (MDM guard — see below)

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell version | 5.1 or higher (64-bit session required) |
| Privileges | Administrator or SYSTEM |
| Firmware | UEFI with Secure Boot supported |
| OS support | Windows 10 1607 LTSC and later, Windows 11 all versions |
| Intune | Microsoft Intune with appropriate licenses (for Proactive Remediation: Intune P2 / Microsoft 365 E3+) |

### Minimum OS Patch Level

The Secure Boot CA 2023 update requires a minimum Windows Update revision (UBR):

| Windows Version | Build | Minimum UBR |
|---|---|---|
| Windows 11 24H2 | 26100 | 1150 |
| Windows 11 23H2 | 22631 | 3880 |
| Windows 11 22H2 | 22621 | 3880 |
| Windows 11 21H2 | 22000 | 3079 |
| Windows 10 22H2 | 19045 | 4651 |
| Windows 10 21H2 | 19044 | 4651 |
| Windows 10 1809 | 17763 | 6054 |
| Windows 10 1607 | 14393 | 7259 |

If the device OS patch level is below the minimum, the detection script will report **Non-Compliant** with a specific message indicating which update is required before Secure Boot CA 2023 can be applied.

---

## Exit Codes

### Detection Script (`Detect-SecureBoot-Certificate-Update.ps1`)

| Exit Code | Meaning | Intune Action |
|---|---|---|
| `0` | Compliant — no action needed | Does **not** run remediation script |
| `1` | Non-Compliant — update required | Runs `Remediate-SecureBoot-Certificate-Update.ps1` |

### Remediation Script (`Remediate-SecureBoot-Certificate-Update.ps1`)

| Exit Code | Meaning | Intune Action |
|---|---|---|
| `0` | Success — remediation applied or already compliant | Marks device as **Remediated** |
| `1` | Failure — could not apply remediation | Marks device as **Failed**, retries on next cycle |

### Unified Script (`Manage-SecureBoot-Certificate-Update.ps1`)

| Exit Code | Meaning |
|---|---|
| `0` | Compliant or successfully remediated |
| `1` | Non-compliant and could not remediate, or script error |

---

## Logging

All three scripts write a structured log file on every run:

```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\<ScriptName>.log
```

| Script | Log File |
|---|---|
| `Manage-SecureBoot-Certificate-Update.ps1` | `Manage-SecureBoot-Certificate-Update.log` |
| `Detect-SecureBoot-Certificate-Update.ps1` | `Detect-SecureBoot-Certificate-Update.log` |
| `Remediate-SecureBoot-Certificate-Update.ps1` | `Remediate-SecureBoot-Certificate-Update.log` |

Log lines are prefixed with `[INFO]`, `[WARN]`, `[ERR]`, or `[VERB]`. Each run writes a fresh log file. The previous two runs are automatically preserved as `.log.1` and `.log.2` alongside the current `.log`, giving you 3 runs of history without manual cleanup.

| File | Contents |
|---|---|
| `<ScriptName>.log` | Current run |
| `<ScriptName>.log.1` | Previous run |
| `<ScriptName>.log.2` | Run before that |

To read the log on a device:

```powershell
Get-Content "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Detect-SecureBoot-Certificate-Update.log"
```

---

## Windows Application Event Log

In addition to the log file, each run writes a single entry to the **Windows Application Event Log** under the source `Intune-SecureBoot-CertUpdate`. This makes compliance and remediation results queryable alongside standard Windows events — useful for SIEM integration or ad-hoc event log queries.

| Event ID | Entry Type | Meaning |
|---|---|---|
| `1000` | Information | Script completed successfully (compliant or remediated) |
| `1001` | Warning | Script completed with a failure (non-compliant, skipped, or error) |

To query the event log on a device:

```powershell
Get-EventLog -LogName Application -Source 'Intune-SecureBoot-CertUpdate' -Newest 10
```

---

## Deployment Guide

### Option A — Intune Proactive Remediation (Recommended)

Use the `Detect` + `Remediate` pair for scheduled, ongoing compliance monitoring. Intune runs the detection script on a defined schedule and only runs the remediation script when non-compliance is detected.

**Steps:**

1. In the **Intune admin center**, go to:
   `Devices > Scripts and remediations > Remediations > Create`

2. Configure the **Basics** tab:
   - Name: `Secure Boot CA 2023 Certificate Update`
   - Description: Detects and remediates the Windows UEFI CA 2023 Secure Boot certificate.

3. Upload the scripts:
   - **Detection script**: `Detect-SecureBoot-Certificate-Update.ps1`
   - **Remediation script**: `Remediate-SecureBoot-Certificate-Update.ps1`

4. Script settings:
   - Run this script using the logged-on credentials: **No**
   - Enforce script signature check: **No** (unless your environment requires it)
   - Run script in 64-bit PowerShell: **Yes** (required)

5. Set a **schedule** (Assignments tab):
   - Recommended: Every 1 hour or Daily
   - Assign to the device group containing your managed Windows endpoints

6. Monitor results in:
   `Devices > Scripts and remediations > Remediations > [your remediation] > Device status`

---

### Option B — Intune Platform Script

Use `Manage-SecureBoot-Certificate-Update.ps1` for a one-time or periodic push via Intune Platform Scripts. The script detects and remediates in a single pass.

**Steps:**

1. In the **Intune admin center**, go to:
   `Devices > Scripts and remediations > Platform scripts > Add > Windows 10 and later`

2. Upload `Manage-SecureBoot-Certificate-Update.ps1`

3. Script settings:
   - Run this script using the logged-on credentials: **No**
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes** (required)

4. Assign to your device group.

> Note: Platform Scripts run once per device (or on re-assignment). Use Proactive Remediations if you need recurring compliance checks.

---

### Option C — Local Execution

All three scripts can be run directly from an elevated PowerShell session:

```powershell
# Run unified script in Auto mode (detect + remediate if needed) — no switch required
.\Manage-SecureBoot-Certificate-Update.ps1

# Run unified script in detection-only mode (no changes made)
.\Manage-SecureBoot-Certificate-Update.ps1 -DetectOnly

# Run unified script in remediation-only mode (skip detection verdict, apply remediation directly)
.\Manage-SecureBoot-Certificate-Update.ps1 -RemediateOnly
# Note: -DetectOnly and -RemediateOnly are mutually exclusive. Specifying both causes an error.

# Run the dedicated detection script (for use outside of Intune Proactive Remediation)
.\Detect-SecureBoot-Certificate-Update.ps1

# Run the dedicated remediation script (for use outside of Intune Proactive Remediation)
.\Remediate-SecureBoot-Certificate-Update.ps1

# Preview remediation changes without applying them (-WhatIf supported)
.\Manage-SecureBoot-Certificate-Update.ps1 -RemediateOnly -WhatIf
.\Remediate-SecureBoot-Certificate-Update.ps1 -WhatIf

# Change log output directory
.\Manage-SecureBoot-Certificate-Update.ps1 -LogPath "C:\Temp\Logs"
```

---

## Intune Settings Catalog — Coexistence and Advantages

### Settings Catalog Policies for Secure Boot CA 2023

The following three Intune Settings Catalog policies can be deployed alongside the scripts:

| Policy Name | Setting | Effect |
|---|---|---|
| Configure Microsoft Update Managed Opt In | Enabled | Opts the device into the Microsoft-managed Secure Boot update path |
| Configure High Confidence Opt Out | Disabled | Prevents devices from opting out of the high-confidence update path |
| Enable Secureboot Certificate Updates | Enabled | Activates the Secure Boot CA 2023 certificate update via Windows Update |

### Can These Be Deployed Together?

**Yes — no conflict.** The scripts contain an **MDM management guard** that automatically detects when the Settings Catalog policies are active by reading `MicrosoftUpdateManagedOptIn = 1`. When detected:

- The remediation script **skips** writing `AvailableUpdates` (which the Settings Catalog policy owns)
- The remediation script **only starts** the scheduled task (a safe, complementary action)
- Both the policies and the scripts continue to function correctly

### Advantages of Deploying Both Together

| Advantage | Settings Catalog Only | Scripts Only | Both Together |
|---|:---:|:---:|:---:|
| Activates Windows Update managed path | Yes | No | Yes |
| Prevents opt-out via High Confidence policy | Yes | No | Yes |
| Direct registry trigger (immediate, no WU dependency) | No | Yes | Yes (scripts) |
| Starts scheduled task immediately | No | Yes | Yes (scripts) |
| Detailed per-device compliance visibility in Intune | No | Yes | Yes |
| Full diagnostics log per device | No | Yes | Yes |
| OS patch level validation | No | Yes | Yes |
| Handles edge cases (InProgress, reboot pending) | No | Yes | Yes |
| Works without Windows Update network access | No | Yes | Yes |
| Fallback if WU path is blocked or delayed | No | Yes | Yes |
| Accelerates update on already-opted-in devices | No | No | Yes |

### Deployment Recommendation

Deploy **both** for maximum coverage:

1. **Settings Catalog policies** ensure devices opt into the Microsoft-managed update path and cannot opt out. This is the long-term, policy-enforced channel.

2. **Proactive Remediation scripts** provide immediate enforcement for devices that have not yet processed the update, give you real-time compliance visibility in Intune, produce detailed diagnostic logs per device, and handle scenarios where the Windows Update path is delayed or blocked.

### Does This Guarantee the Certificate Will Be Updated?

Deploying both significantly increases the probability of successful deployment, but a few conditions must still be met:

| Condition | Required |
|---|---|
| Device is UEFI (not legacy BIOS) | Yes — scripts and policies skip BIOS devices |
| Secure Boot is enabled | Yes — certificate cannot be applied without it |
| OS patch level meets the minimum UBR | Yes — scripts report this if not met |
| Device is not a virtual machine | Recommended — VMs are skipped by default |
| A system reboot completes after triggering | Yes — the certificate is applied during a reboot |

> After triggering remediation, a system reboot is required to complete the certificate deployment. The scripts report the reboot-pending state in the log and in the Intune device status output. Full deployment across all certificate components (DB, KEK, BootMgr) typically requires **~48 hours and multiple restarts** to complete in sequence, as the Windows scheduled task runs on a 12-hour cycle.

---

## Monitored Registry Keys

| Key Path | Value Name | Description |
|---|---|---|
| `HKLM:\...\SecureBoot\Servicing` | `UEFICA2023Status` | Update process state: `Updated`, `InProgress`, `NotStarted` |
| `HKLM:\...\SecureBoot\Servicing` | `WindowsUEFICA2023Capable` | Device capability flag: `0x2` = capable and confirmed |
| `HKLM:\...\SecureBoot\Servicing` | `UEFICA2023Error` | Error code if the update failed |
| `HKLM:\...\SecureBoot\Servicing` | `UEFICA2023ErrorEvent` | Event ID associated with the error |
| `HKLM:\...\SecureBoot` | `AvailableUpdates` | Update trigger bitmask; scripts set this to `0x5944` |
| `HKLM:\...\SecureBoot` | `AvailableUpdatesPolicy` | GPO-managed equivalent of `AvailableUpdates` (domain-joined devices; read-only, monitored for diagnostics) |
| `HKLM:\...\SecureBoot` | `MicrosoftUpdateManagedOptIn` | `1` = Settings Catalog MDM policy is active |
| `HKLM:\...\SecureBoot` | `HighConfidenceOptOut` | `0` = High Confidence Opt Out policy is disabled (expected) |

Full path: `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot`

### AvailableUpdates Bitmask (`0x5944`)

| Bit | Hex | Component |
|---|---|---|
| DB update | `0x0040` | Adds Windows UEFI CA 2023 to Secure Boot DB |
| KEK update | `0x0004` | Adds KEK 2K CA 2023 |
| DBX update | `0x0002` | Applies latest revocations |
| BootMgr install | `0x0100` | Installs 2023 Boot Manager (PCA2023 chain) |
| SVN update | `0x0200` | Anti-rollback counter update |
| SBAT update | `0x0400` | Firmware targeting via SBAT |
| Option ROM CA | `0x0800` | Adds Option ROM CA 2023 to DB |
| UEFI CA 2023 | `0x1000` | Adds Microsoft UEFI CA 2023 to DB |
| Post-reboot stage | `0x4000` | Post-reboot phase of BootMgr update |

---

## Known Hardware and Platform Issues

The following issues are documented by Microsoft and community sources and may prevent or affect the Secure Boot CA 2023 update on specific hardware or platform configurations.

### Hyper-V Virtual Machines

KEK certificate updates fail on Hyper-V VMs with error code `800703e6`. The `UEFICA2023Status` stays `InProgress` indefinitely and will never resolve inside the VM.

**Action:** Do not attempt to remediate the VM itself — apply the Secure Boot CA 2023 update on the **Hyper-V host** instead. The scripts detect Hyper-V VMs automatically and skip remediation with a specific warning.

### VMware ESXi Virtual Machines

KEK updates fail on VMware VMs by default because the virtual UEFI implementation does not allow firmware variable writes.

**Workaround:** Set `uefi.allowAuthBypass=TRUE` in the VM's advanced configuration on the ESXi host to enable manual UEFI variable enrollment. The scripts detect VMware VMs and skip remediation with guidance in the log.

### HP "Sure Start" Firmware

HP devices with Sure Start enabled may fail to boot after a failed Secure Boot update if the BIOS firmware is outdated.

**Action:** Always apply the latest HP BIOS/firmware update **before** running the Secure Boot CA 2023 update on HP Sure Start devices.

### Windows Pro → Enterprise Subscription Upgrade

Devices originally shipped with OEM Windows Pro and later upgraded to Windows Enterprise via subscription activation may receive Intune error `65000` when the Settings Catalog Secure Boot policies are applied. This is an OS-level licensing check that rejects the policy before it is processed.

**Action:** This is an Intune-side issue unrelated to these scripts. Contact Microsoft Support or verify the device is fully enrolled as an Enterprise device. The Proactive Remediation scripts are not affected by this error.

### Intune Native Secure Boot Status Report

Microsoft Intune includes a native **Secure Boot Status Report** (`Devices > Monitor > Secure Boot status`). This report is populated by Windows diagnostic telemetry via the `SBServicingCoreTelemetryProvider`. The **"Windows Diagnostic data with Intune"** data connector must be configured; without it the report blade will be empty even when devices are compliant.

This report is separate from and complementary to the per-device compliance data produced by the Proactive Remediation scripts.

### Domain-Joined Devices — WinCS Alternative

For Windows 11 23H2, 24H2, and 25H2 **domain-joined** devices, Microsoft provides a command-line alternative called **WinCS** (Windows Configuration System). Use feature name `Feature_AllKeysAndBootMgrByWinCS` with key value `F33E0C8E002` to trigger the update without Intune or direct registry editing.

This method is not applicable to Intune-only or workgroup environments.

---

## License

MIT License — free to use and modify with attribution.
