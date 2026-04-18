<#PSScriptInfo
.VERSION        1.0.0
.AUTHOR         Yoennis Olmo
.COPYRIGHT      MIT License - free to use with attribution.
.TAGS           Intune SecureBoot UEFI Certificate Remediation Detection
.RELEASENOTES
    1.0.0 - Initial unified release combining best features of multiple Secure Boot CA 2023 scripts.
            Detection and remediation in a single self-contained script.
#>

<#
.SYNOPSIS
    Unified Secure Boot Windows UEFI CA 2023 - Detection and Remediation Script.

.DESCRIPTION
    Single-script solution for detecting and remediating the Secure Boot Windows UEFI CA 2023
    certificate requirement on Windows devices.

    Designed to run as:
      - Intune Platform Script (Auto mode: detects and remediates in one pass — no switch needed)
      - Intune Proactive Remediation (Detection or Remediation script, auto-detected from filename)
      - Local standalone execution by an administrator

    Detection logic (two independent checks, either is sufficient for compliance):
      1. Binary X.509 parse of the Secure Boot UEFI DB for 'Windows UEFI CA 2023' certificate
      2. Registry status keys: UEFICA2023Status = 'Updated' AND WindowsUEFICA2023Capable = 2

    Remediation steps (only when non-compliant and mode permits):
      1. Creates the registry path if missing
      2. Sets HKLM:\...\SecureBoot\AvailableUpdates = 0x5944 (full update flag set)
      3. Starts the Windows built-in scheduled task \Microsoft\Windows\PI\Secure-Boot-Update
      4. A system reboot may be required to complete the certificate deployment

    Diagnostics collected and logged:
      - Secure Boot state and full certificate list (PK, KEK, DB) with subjects and thumbprints
      - Firmware type (UEFI vs BIOS), version, and date
      - TPM presence, version, enabled state, and latest event log entry
      - Hardware make, model, and virtual machine detection
      - Disk partition style (GPT vs MBR)
      - OS version and patch level vs. required minimum for the Secure Boot update
      - All relevant Secure Boot registry key values
      - MicrosoftUpdateManagedOptIn opt-in state

    Logging:
      All output is captured and saved to:
      C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\<ScriptName>.log

    Safety:
      - Never removes or modifies existing certificates
      - Only sets the trigger for Windows' own built-in update mechanism
      - Skips remediation on BIOS/Legacy, Secure Boot disabled, or incompatible devices
      - Idempotent: safe to run multiple times

.PARAMETER DetectOnly
    Only check and report compliance. No registry or task changes are made.
    When omitted, the script runs in Auto mode (detect, then remediate if non-compliant).

.PARAMETER RemediateOnly
    Skip the detection verdict and directly apply remediation steps.
    Useful for forcing a remediation attempt regardless of current compliance state.

.PARAMETER LogPath
    Directory where the log file is written.
    Default: C:\ProgramData\Microsoft\IntuneManagementExtension\Logs

.EXAMPLE
    .\Manage-SecureBoot-Certificate-Update.ps1
    Runs in Auto mode (default). Detects and remediates if needed. No switch required.

.EXAMPLE
    .\Manage-SecureBoot-Certificate-Update.ps1 -DetectOnly
    Only checks compliance. Reports status. Makes no changes.

.EXAMPLE
    .\Manage-SecureBoot-Certificate-Update.ps1 -RemediateOnly
    Skips detection verdict and directly applies remediation steps.

.NOTES
    Requirements:
      - PowerShell 5.1 or higher (64-bit)
      - Administrator or SYSTEM privileges
      - UEFI firmware with Secure Boot supported and enabled
    A reboot may be required after remediation to complete the certificate deployment.
    Use -Verbose to enable detailed diagnostic output including EFI DB binary parse trace.
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false, HelpMessage = 'Only check compliance. No changes made.')]
    [switch]$DetectOnly,

    [Parameter(Mandatory = $false, HelpMessage = 'Skip detection verdict and directly apply remediation.')]
    [switch]$RemediateOnly,

    [Parameter(Mandatory = $false, HelpMessage = 'Directory where log files are saved')]
    [string]$LogPath = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
)

#region ---[Modifiable Configuration]---

$ScriptName    = 'Manage-SecureBoot-Certificate-Update'
$ScriptVersion = '1.0.0'

# -----------------------------------------------------------------------
# Remediation: registry trigger value.
# 0x5944 = all relevant update flags:
#   0x0040 DB update (add Windows UEFI CA 2023)
#   0x0004 KEK update (add KEK 2K CA 2023)
#   0x0002 DBX update (apply latest revocations)
#   0x0100 Install 2023 BootMgr (PCA2023 chain)
#   0x0200 SVN update (anti-rollback counter)
#   0x0400 SBAT update (firmware targeting)
#   0x0800 Option ROM CA 2023 -> DB
#   0x1000 Microsoft UEFI CA 2023 -> DB
#   0x4000 Post reboot stage during BootMgr update
# -----------------------------------------------------------------------
$AvailableUpdatesValue = 0x5944
$RemediateRegPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
$RemediateRegKey       = 'AvailableUpdates'
$RemediateTaskPath     = '\Microsoft\Windows\PI\'
$RemediateTaskName     = 'Secure-Boot-Update'

# Registry keys read for status monitoring and diagnostics
$registryKeysStatus = @(
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'; Key = 'UEFICA2023Status';            Description = 'Update status'      }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'; Key = 'WindowsUEFICA2023Capable';    Description = 'Device capability'   }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'; Key = 'UEFICA2023Error';             Description = 'Error code'          }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'; Key = 'UEFICA2023ErrorEvent';        Description = 'Error event ID'      }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot';           Key = 'AvailableUpdates';            Description = 'Update trigger'      }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot';           Key = 'MicrosoftUpdateManagedOptIn'; Description = 'Managed opt-in flag' }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot';           Key = 'AvailableUpdatesPolicy';      Description = 'GPO update trigger'  }
)

# Minimum OS update revision (UBR) required per Windows build for the Secure Boot CA 2023 update.
# Patch = 0 means any revision of that build is sufficient (e.g. Insider builds).
$OSversions = @(
    @{ Name = 'Insider';          Build = 26200; Patch = 0    }
    @{ Name = 'Windows 11 24H2';  Build = 26100; Patch = 1150 }
    @{ Name = 'Windows 11 23H2';  Build = 22631; Patch = 3880 }
    @{ Name = 'Windows 11 22H2';  Build = 22621; Patch = 3880 }
    @{ Name = 'Windows 11 21H2';  Build = 22000; Patch = 3079 }
    @{ Name = 'Windows 10 22H2';  Build = 19045; Patch = 4651 }
    @{ Name = 'Windows 10 21H2';  Build = 19044; Patch = 4651 }
    @{ Name = 'Windows 10 1809';  Build = 17763; Patch = 6054 }
    @{ Name = 'Windows 10 1607';  Build = 14393; Patch = 7259 }
)

# -----------------------------------------------------------------------
# Intune Settings Catalog — Secure Boot CA 2023 policy detection.
#
# When the following three Settings Catalog policies are deployed from Intune,
# they write to specific registry keys. The script reads these to detect whether
# MDM is already managing the Secure Boot update process. If detected, the
# remediation step will NOT write AvailableUpdates (to avoid conflicting with
# the MDM-managed value), and will only start the scheduled task as a safe
# complementary action.
#
# Policy 1: 'Configure Microsoft Update Managed Opt In = Enabled'
#   Effective key: HKLM:\...\SecureBoot\MicrosoftUpdateManagedOptIn = 1
#   This is the definitive indicator — presence of value=1 means the full
#   Settings Catalog policy set is active.
#
# Policy 2: 'Configure High Confidence Opt Out = Disabled'
#   Effective key: HKLM:\...\SecureBoot\HighConfidenceOptOut = 0 (or absent)
#   When Disabled: devices cannot opt out of the high-confidence update path.
#
# Policy 3: 'Enable Secureboot Certificate Updates = Enabled'
#   This policy triggers the update. It sets AvailableUpdates via MDM and/or
#   starts the Windows Update mechanism. The script must NOT overwrite this.
#   Detection relies on MicrosoftUpdateManagedOptIn=1 as the indicator.
# -----------------------------------------------------------------------
$MDMPolicyPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'

# Windows Application event log source name for compliance and remediation results.
$EventSource   = 'Intune-SecureBoot-CertUpdate'

#endregion

#region ---[Execution Mode Detection]---
# Derive $Mode from switch parameters. Default is Auto when neither switch is provided.
$Mode = if ($DetectOnly) { 'DetectOnly' } elseif ($RemediateOnly) { 'RemediateOnly' } else { 'Auto' }

# Auto-detect if running as part of an Intune Proactive Remediation pair based on filename.
# Filename takes priority over switch parameters to align with Intune conventions.
if ($PSCommandPath) {
    $scriptLeaf = Split-Path $PSCommandPath -Leaf
    if ($scriptLeaf -imatch 'Detect') {
        $Mode = 'DetectOnly'
    } elseif ($scriptLeaf -imatch 'Remediat') {
        $Mode = 'Auto'   # In remediation file context, Auto = detect then remediate
    }
}
#endregion

#region ---[Functions]---

function Invoke-ScriptLog {
    <#
    .SYNOPSIS
        Structured script logger for PowerShell 5.1+.
        Intercepts all Write-Host/Output/Warning/Error/Verbose calls, buffers messages in memory,
        and on Stop flushes to a .log file on disk and returns the full log array.
    .PARAMETER Mode   Start | Stop
    .PARAMETER Name   Log file base name (no extension)
    .PARAMETER LogPath  Directory for the log file
    #>
    param(
        [ValidateSet('Start', 'Stop')]
        [string]$Mode = 'Start',
        [string]$Name    = 'TinyLog',
        [string]$LogPath = $PSScriptRoot
    )

    if ($Mode -eq 'Start') {
        if (-not $script:_log) {
            $script:_log = New-Object 'System.Collections.Generic.List[string]'
            function global:Write-Host {
                $m = $args -join ' '
                if ($m) { $script:_log.Add("[INFO]  $m"); Microsoft.PowerShell.Utility\Write-Host "[INFO]  $m" }
            }
            function global:Write-Output {
                $m = $args -join ' '
                if ($m) { $script:_log.Add("[INFO]  $m"); Microsoft.PowerShell.Utility\Write-Host "[INFO]  $m" }
            }
            function global:Write-Warning {
                $m = $args -join ' '
                if ($m) { $script:_log.Add("[WARN]  $m"); Microsoft.PowerShell.Utility\Write-Host "[WARN]  $m" -ForegroundColor Yellow }
            }
            function global:Write-Error {
                $m = $args -join ' '
                if ($m) { $script:_log.Add("[ERR]   $m"); Microsoft.PowerShell.Utility\Write-Host "[ERR]   $m" -ForegroundColor Red }
            }
            function global:Write-Verbose {
                $m = $args -join ' '
                if ($m) {
                    $script:_log.Add("[VERB]  $m")
                    if ($VerbosePreference -ne 'SilentlyContinue') {
                        Microsoft.PowerShell.Utility\Write-Host "[VERB]  $m" -ForegroundColor Cyan
                    }
                }
            }
        }
    } else {
        # Restore original Write-* cmdlets
        'Write-Host', 'Write-Output', 'Write-Warning', 'Write-Error', 'Write-Verbose' |
            ForEach-Object { Remove-Item "function:$_" -ErrorAction SilentlyContinue }

        if ($script:_log) {
            try {
                if (-not (Test-Path $LogPath)) {
                    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
                }
                $logFile = Join-Path $LogPath "$Name.log"
                # Log rotation: keep the last 2 archived runs alongside the current log.
                # Result: <Name>.log (current), <Name>.log.1 (previous), <Name>.log.2 (oldest kept)
                $log2 = Join-Path $LogPath "$Name.log.2"
                $log1 = Join-Path $LogPath "$Name.log.1"
                if (Test-Path $log2)    { Remove-Item $log2 -Force -ErrorAction SilentlyContinue }
                if (Test-Path $log1)    { Move-Item $log1 $log2 -Force -ErrorAction SilentlyContinue }
                if (Test-Path $logFile) { Move-Item $logFile $log1 -Force -ErrorAction SilentlyContinue }
                [System.IO.File]::WriteAllLines($logFile, $script:_log)
            } catch {
                # Non-fatal: log flush failure should not crash the script
            }
            , $script:_log.ToArray()
            $script:_log = $null
        } else {
            , @()
        }
    }
}

function Confirm-Prerequisites {
    <#
    .SYNOPSIS
        Validates that the script is running with the required privileges and PowerShell bitness.
    .OUTPUTS
        [bool] $true if all requirements are met.
    #>
    $ok = $true

    # Must be 64-bit: Get-SecureBootUEFI is only available in 64-bit PowerShell
    if ([IntPtr]::Size -ne 8) {
        Write-Warning "Requires 64-bit PowerShell (currently $([IntPtr]::Size * 8)-bit). Cannot access Secure Boot UEFI API."
        $ok = $false
    }

    # Must be Administrator or SYSTEM
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isSystem = $identity.User.Value -eq 'S-1-5-18'
    $isAdmin  = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not ($isSystem -or $isAdmin)) {
        Write-Warning "Requires Administrator or SYSTEM privileges (currently: $($identity.Name))."
        $ok = $false
    }

    return $ok
}

function Get-SecureBootCertSubjects {
    <#
    .SYNOPSIS
        Parses a Secure Boot EFI signature database (db, dbx, kek, pk) using the binary EFI
        Signature List format. Returns structured objects for each entry.
    .DESCRIPTION
        Walks the raw byte array offset by offset, identifies entry types by GUID
        (X.509 certificate or SHA-256 hash), extracts and loads each certificate as a
        .NET X509Certificate2 object, and returns an array of PSCustomObjects with
        SignatureSubject, Thumbprint, NotAfter, and raw Certificate properties.
    .PARAMETER Database
        Name of the UEFI variable to read: db, dbx, kek, or pk.
    .OUTPUTS
        [PSCustomObject[]] array of signature entries.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Database
    )

    try {
        $raw = Get-SecureBootUEFI -Name $Database -ErrorAction Stop
    } catch {
        Write-Verbose "Cannot read Secure Boot database '$Database': $($_.Exception.Message)"
        return @()
    }

    $bytes               = $raw.Bytes
    $EFI_CERT_X509_GUID  = [guid]'a5c059a1-94e4-4aa7-87b5-ab155c2bf072'
    $EFI_CERT_SHA256_GUID= [guid]'c1c41626-504c-4092-aca9-41f936934328'
    $results             = @()
    $offset              = 0

    while ($offset -lt $bytes.Length) {
        try {
            $typeGuid          = [Guid][Byte[]]$bytes[$offset..($offset + 15)]
            $listSize          = [BitConverter]::ToUInt32($bytes, $offset + 16)
            $signatureSize     = [BitConverter]::ToUInt32($bytes, $offset + 24)

            if ($listSize -lt 28 -or $signatureSize -eq 0) { break }

            $signatureCount    = [Math]::Floor(($listSize - 28) / $signatureSize)
            $so                = $offset + 28

            for ($i = 0; $i -lt $signatureCount; $i++) {
                $owner = [Guid][Byte[]]$bytes[$so..($so + 15)]

                if ($typeGuid -eq $EFI_CERT_X509_GUID) {
                    $certBytes = [Byte[]]$bytes[($so + 16)..($so + $signatureSize - 1)]
                    try {
                        if ($PSEdition -eq 'Core') {
                            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                        } else {
                            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                            $cert.Import($certBytes)
                        }
                        $results += [PSCustomObject]@{
                            Type             = 'X509'
                            SignatureOwner   = $owner
                            SignatureSubject = $cert.Subject
                            Thumbprint       = $cert.Thumbprint
                            NotAfter         = $cert.NotAfter
                            Certificate      = $cert
                        }
                    } catch {
                        $results += [PSCustomObject]@{
                            Type             = 'X509'
                            SignatureOwner   = $owner
                            SignatureSubject = 'Certificate parse error'
                            Thumbprint       = ''
                            NotAfter         = $null
                            Certificate      = $null
                        }
                    }
                } elseif ($typeGuid -eq $EFI_CERT_SHA256_GUID) {
                    $hash = ([Byte[]]$bytes[($so + 16)..($so + 47)] | ForEach-Object { $_.ToString('X2') }) -join ''
                    $results += [PSCustomObject]@{
                        Type             = 'SHA256'
                        SignatureOwner   = $owner
                        SignatureSubject = "SHA256:$hash"
                        Thumbprint       = $hash
                        NotAfter         = $null
                        Certificate      = $null
                    }
                } else {
                    $results += [PSCustomObject]@{
                        Type             = 'Unknown'
                        SignatureOwner   = $owner
                        SignatureSubject = "Unknown GUID: $typeGuid"
                        Thumbprint       = ''
                        NotAfter         = $null
                        Certificate      = $null
                    }
                }
                $so += $signatureSize
            }
            $offset += $listSize
        } catch {
            Write-Verbose "EFI DB parse error at offset $offset`: $($_.Exception.Message)"
            break
        }
    }
    return $results
}

function Get-RegistryValues {
    <#
    .SYNOPSIS
        Safely reads a single registry value. Returns $null if path or key does not exist.
    #>
    param(
        [string]$Path,
        [string]$Key
    )
    if (-not (Test-Path $Path)) { return $null }
    try {
        return (Get-ItemProperty -Path $Path -Name $Key -ErrorAction Stop).$Key
    } catch {
        return $null
    }
}

function Get-SecureBootDiagnostics {
    <#
    .SYNOPSIS
        Collects comprehensive system diagnostics relevant to Secure Boot CA 2023 compliance.
    .DESCRIPTION
        Returns an ordered hashtable containing Secure Boot state, certificate subjects,
        firmware info, TPM state, hardware details, OS version/patch level,
        and all monitored registry key values.
    .PARAMETER RegistryKeys
        Array of hashtables with Path, Key, Description for registry keys to read.
    .PARAMETER OSVersions
        Array of hashtables with Name, Build, Patch for OS version patch level checks.
    .OUTPUTS
        [System.Collections.Specialized.OrderedDictionary]
    #>
    param(
        [hashtable[]]$RegistryKeys = $null,
        [hashtable[]]$OSVersions   = $null
    )

    $diag = [ordered]@{}

    try {
        # ---- Secure Boot enabled state ----
        try {
            $sbEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            $diag['SecureBootEnabled'] = if ($sbEnabled) { 'Enabled' } else { 'Disabled' }
        } catch {
            $diag['SecureBootEnabled'] = 'Disabled/Unsupported'
        }

        # ---- Secure Boot certificate databases (binary X.509 parsed) ----
        $pkCerts  = Get-SecureBootCertSubjects -Database pk
        $kekCerts = Get-SecureBootCertSubjects -Database kek
        $dbCerts  = Get-SecureBootCertSubjects -Database db

        $diag['SecureBootPK']  = if ($pkCerts) {
            ($pkCerts  | ForEach-Object { if ($_.SignatureSubject -match 'CN=([^,]+)') { $matches[1] } else { $_.SignatureSubject } }) -join '; '
        } else { '(none or unreadable)' }

        $diag['SecureBootKEK'] = if ($kekCerts) {
            ($kekCerts | ForEach-Object { if ($_.SignatureSubject -match 'CN=([^,]+)') { $matches[1] } else { $_.SignatureSubject } }) -join '; '
        } else { '(none or unreadable)' }

        $diag['SecureBootDB']  = if ($dbCerts) {
            ($dbCerts  | ForEach-Object { if ($_.SignatureSubject -match 'CN=([^,]+)') { $matches[1] } else { $_.SignatureSubject } }) -join '; '
        } else { '(none or unreadable)' }

        # Primary compliance indicator
        $has2023 = ($dbCerts | Where-Object { $_.SignatureSubject -match 'Windows UEFI CA 2023' })
        $diag['SecureBootDBHas2023'] = [bool]$has2023

        # ---- Firmware type (UEFI vs BIOS/Legacy) ----
        try {
            $bcdeditOutput = & bcdedit /enum firmware 2>&1
            $diag['FirmwareType'] = if ($bcdeditOutput -match '\.efi') { 'UEFI' } else { 'BIOS/Legacy' }
        } catch {
            # Fallback: check for UEFI-specific registry path
            $diag['FirmwareType'] = if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State') { 'UEFI' } else { 'BIOS/Legacy' }
        }

        $bios = Get-CimInstance Win32_BIOS -Property SMBIOSBIOSVersion, ReleaseDate -ErrorAction SilentlyContinue
        $diag['FirmwareVersion'] = if ($bios) { $bios.SMBIOSBIOSVersion } else { 'Unknown' }
        $diag['FirmwareDate']    = if ($bios -and $bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { 'Unknown' }

        # ---- TPM ----
        $tpm = Get-CimInstance -Namespace 'Root\CIMv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        $diag['TPMPresent'] = [bool]$tpm
        $diag['TPMEnabled'] = if ($tpm) { $tpm.IsEnabled_InitialValue } else { 'N/A' }
        $diag['TPMVersion'] = if ($tpm -and $tpm.SpecVersion) { ($tpm.SpecVersion -split ',')[0].Trim() } else { 'N/A' }

        # TPM event log: 1808 = Secure Boot update success, 1801 = failure
        try {
            $tpmEvt = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = 'Microsoft-Windows-TPM-WMI'
                Id           = @(1808, 1801)
            } -MaxEvents 1 -ErrorAction SilentlyContinue

            if ($tpmEvt) {
                $msgShort = ($tpmEvt.Message -replace '\s+', ' ')
                if ($msgShort.Length -gt 160) { $msgShort = $msgShort.Substring(0, 160) + '...' }
                $diag['TPMLastEvent'] = "$($tpmEvt.Id) @ $($tpmEvt.TimeCreated.ToString('s')) - $msgShort"
            } else {
                $diag['TPMLastEvent'] = 'No relevant events (1808/1801)'
            }
        } catch {
            $diag['TPMLastEvent'] = 'Event log unavailable'
        }

        # Secure Boot firmware error events: 1795 = certificate handoff error, 1796 = KEK update failure
        try {
            $sbFirmEvt = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                Id      = @(1795, 1796)
            } -MaxEvents 1 -ErrorAction SilentlyContinue
            $diag['SecureBootFirmwareEvent'] = if ($sbFirmEvt) {
                $msgShort = ($sbFirmEvt.Message -replace '\s+', ' ')
                if ($msgShort.Length -gt 160) { $msgShort = $msgShort.Substring(0, 160) + '...' }
                "$($sbFirmEvt.Id) @ $($sbFirmEvt.TimeCreated.ToString('s')) - $msgShort"
            } else {
                'No relevant events (1795/1796)'
            }
        } catch {
            $diag['SecureBootFirmwareEvent'] = 'Event log unavailable'
        }

        # ---- Hardware ----
        $cs = Get-CimInstance Win32_ComputerSystem -Property Manufacturer, Model -ErrorAction SilentlyContinue
        $diag['HWMake']  = if ($cs) { $cs.Manufacturer } else { 'Unknown' }
        $diag['HWModel'] = if ($cs) { $cs.Model }        else { 'Unknown' }
        $diag['HWIsVM']  = if ($cs -and ($cs.Model -match 'Virtual|VMware|VirtualBox|Hyper-V|QEMU|Parallels|domU|Nutanix' -or
                                          $cs.Manufacturer -match 'Xen|Nutanix')) {
            'Yes'
        } elseif ($cs) { 'No' } else { 'Unknown' }

        try {
            $osDisk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.IsBoot -eq $true } | Select-Object -First 1
            $diag['HWDiskPartition'] = if ($osDisk) { $osDisk.PartitionStyle } else { 'Unknown' }
        } catch {
            $diag['HWDiskPartition'] = 'Unknown'
        }

        # ---- OS version and patch level ----
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
        $buildStr = if ($cv -and $cv.CurrentBuildNumber) { $cv.CurrentBuildNumber } elseif ($cv -and $cv.CurrentBuild) { $cv.CurrentBuild } else { $null }
        $build = if ($buildStr) { try { [int]$buildStr } catch { $null } } else { $null }
        $patch = if ($cv -and $null -ne $cv.UBR) { try { [int]$cv.UBR } catch { $null } } else { $null }

        if ($OSVersions -and $null -ne $build) {
            $sortedOS = $OSVersions | Sort-Object { [int]$_.Build } -Descending
            $osMatch  = $sortedOS | Where-Object { [int]$_.Build -le $build } | Select-Object -First 1

            if ($osMatch) {
                $diag['OSVersion'] = "$($osMatch.Name) (Build $build.$patch)"
                if ($osMatch.Patch -eq 0) {
                    $patchOk = $true
                } elseif ($null -ne $patch -and $patch -ge $osMatch.Patch) {
                    $patchOk = $true
                } else {
                    $patchOk = $false
                }
                $diag['OSPatchCompliant'] = [bool]$patchOk
                $diag['OSMinPatchNeeded'] = if (-not $patchOk) { "$($osMatch.Name) requires patch >= $($osMatch.Patch), current = $patch" } else { 'OK' }
            } else {
                $diag['OSVersion']        = "Unrecognized (Build $build.$patch)"
                $diag['OSPatchCompliant'] = 'Unknown'
                $diag['OSMinPatchNeeded'] = 'N/A - unrecognized build'
            }
        } else {
            $diag['OSVersion']        = 'Unknown'
            $diag['OSPatchCompliant'] = 'Unknown'
            $diag['OSMinPatchNeeded'] = 'N/A'
        }

        # ---- Monitored registry keys ----
        if ($RegistryKeys) {
            foreach ($rk in $RegistryKeys) {
                try {
                    $val = Get-RegistryValues -Path $rk.Path -Key $rk.Key
                    if ($null -eq $val) {
                        $diag["Reg:$($rk.Key)"] = '(not set)'
                    } elseif ($val -is [int]) {
                        $diag["Reg:$($rk.Key)"] = '0x{0:X}' -f $val
                    } else {
                        $diag["Reg:$($rk.Key)"] = $val
                    }
                } catch {
                    $diag["Reg:$($rk.Key)"] = '(error reading)'
                }
            }
        }

        # ---- UEFICA2023ErrorEvent System log cross-reference ----
        # If the registry records an error event ID, look it up in the System log for the full message.
        $errEvtVal = $diag['Reg:UEFICA2023ErrorEvent']
        if ($null -ne $errEvtVal -and $errEvtVal -ne '(not set)' -and $errEvtVal -ne '0x0') {
            try {
                $errEvtInt = if ($errEvtVal -match '^0x([0-9A-Fa-f]+)$') {
                    [Convert]::ToInt32($matches[1], 16)
                } elseif ($errEvtVal -match '^\d+$') {
                    [int]$errEvtVal
                } else { $null }

                if ($null -ne $errEvtInt -and $errEvtInt -ne 0) {
                    $errEvt = Get-WinEvent -FilterHashtable @{
                        LogName = 'System'
                        Id      = $errEvtInt
                    } -MaxEvents 1 -ErrorAction SilentlyContinue
                    $diag['UEFICA2023ErrorEventDetail'] = if ($errEvt) {
                        $msgShort = ($errEvt.Message -replace '\s+', ' ')
                        if ($msgShort.Length -gt 200) { $msgShort = $msgShort.Substring(0, 200) + '...' }
                        "Event $($errEvt.Id) @ $($errEvt.TimeCreated.ToString('s')) - $msgShort"
                    } else {
                        "Event ID $errEvtInt not found in System log"
                    }
                }
            } catch {
                $diag['UEFICA2023ErrorEventDetail'] = "Could not query System log for Event ID $errEvtVal"
            }
        }

        # ---- Intune Settings Catalog policy state ----
        # MicrosoftUpdateManagedOptIn = 1 is the definitive indicator that the
        # 'Configure Microsoft Update Managed Opt In = Enabled' Settings Catalog
        # policy has been applied. It also implies the other two Secure Boot
        # CA 2023 policies from the same policy set are active.
        $mdmOptIn    = Get-RegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Key 'MicrosoftUpdateManagedOptIn'
        $mdmHCOptOut = Get-RegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Key 'HighConfidenceOptOut'

        $diag['MDM:MicrosoftUpdateManagedOptIn'] = if ($mdmOptIn -eq 1) {
            'Enabled — Settings Catalog policy applied'
        } else {
            "(value=$mdmOptIn - policy not detected)"
        }

        $diag['MDM:HighConfidenceOptOut'] = if ($null -eq $mdmHCOptOut) {
            '(not set)'
        } elseif ($mdmHCOptOut -eq 0) {
            '0 = Disabled — Settings Catalog policy applied'
        } else {
            "$mdmHCOptOut - unexpected value, opt-out may be active"
        }

        # Check MDM PolicyManager for any Secure Boot or Update related sub-keys.
        # These would indicate enrolled CSP policies beyond the effective registry keys.
        try {
            $policySubKeys = Get-ChildItem -Path $MDMPolicyPath -ErrorAction SilentlyContinue |
                             Where-Object { $_.PSChildName -imatch 'SecureBoot|Update' }
            $diag['MDM:PolicyManagerKeys'] = if ($policySubKeys) {
                ($policySubKeys | Select-Object -ExpandProperty PSChildName) -join '; '
            } else {
                'None detected'
            }
        } catch {
            $diag['MDM:PolicyManagerKeys'] = 'Unable to query'
        }

        # Derived flag: $true when MicrosoftUpdateManagedOptIn=1.
        # Used by Invoke-Remediation to decide whether to write AvailableUpdates.
        $diag['MDMManagesSecureBoot'] = [bool]($mdmOptIn -eq 1)

        # ---- Pending reboot detection ----
        # A pending reboot can explain why Secure Boot updates have not yet been applied.
        $rebootRequired = $false
        $rebootSources  = [System.Collections.Generic.List[string]]::new()
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
            $rebootRequired = $true; $rebootSources.Add('WindowsUpdate')
        }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            $rebootRequired = $true; $rebootSources.Add('CBS')
        }
        $diag['PendingReboot'] = if ($rebootRequired) {
            "Yes - reboot pending from: $($rebootSources -join ', ')"
        } else { 'No' }

    } catch {
        Write-Warning "Diagnostics collection encountered an error: $($_.Exception.Message)"
    }

    return $diag
}

function Invoke-Detection {
    <#
    .SYNOPSIS
        Evaluates compliance based on previously collected diagnostics.
    .DESCRIPTION
        Checks compliance in this order:
          1. Primary   : Windows UEFI CA 2023 present in the Secure Boot DB (binary-parsed X.509).
          2. Early exit: Secure Boot disabled or legacy BIOS — cannot be compliant.
          3. Secondary : Full state machine on UEFICA2023Status registry key:
               Updated    + Capable=0x2 + no error  -> Compliant
               Updated    + Capable<>0x2 or error   -> Non-Compliant (unexpected state, investigate)
               InProgress + AvailableUpdates has 0x4100 -> Compliant, reboot pending
               InProgress (other)                   -> Compliant, update in progress
               NotStarted + trigger already=0x5944  -> Compliant, waiting for task
               NotStarted (trigger not set)         -> Non-Compliant, needs remediation
               (not set)                            -> Non-Compliant, update not started
               default                              -> Non-Compliant, unknown state
    .OUTPUTS
        [bool] $true = Compliant, $false = Non-Compliant
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$Diagnostics
    )

    # PRIMARY: certificate physically present in Secure Boot DB
    if ($Diagnostics['SecureBootDBHas2023'] -eq $true) {
        Write-Host 'COMPLIANT: Windows UEFI CA 2023 certificate found in Secure Boot DB (binary-verified).'
        return $true
    }

    # EARLY EXIT: fundamental prerequisites — if these fail the state machine is meaningless
    if ($Diagnostics['SecureBootEnabled'] -notmatch 'Enabled') {
        Write-Warning "NON-COMPLIANT: Secure Boot is '$($Diagnostics['SecureBootEnabled'])'. The CA 2023 certificate cannot be applied without Secure Boot enabled."
        return $false
    }
    if ($Diagnostics['FirmwareType'] -ne 'UEFI') {
        Write-Warning "NON-COMPLIANT: Legacy BIOS/non-UEFI firmware detected. Secure Boot CA 2023 requires UEFI firmware."
        return $false
    }

    # Read all relevant registry state values
    $status    = $Diagnostics['Reg:UEFICA2023Status']
    $capable   = $Diagnostics['Reg:WindowsUEFICA2023Capable']
    $errCode   = $Diagnostics['Reg:UEFICA2023Error']
    $errEvent  = $Diagnostics['Reg:UEFICA2023ErrorEvent']
    $noError   = ($errCode -eq '(not set)' -or $errCode -eq '0x0' -or $null -eq $errCode)

    # Parse AvailableUpdates hex string to integer for bitwise comparisons
    $availableStr = $Diagnostics['Reg:AvailableUpdates']
    $availableInt = 0
    if ($availableStr -match '^0x([0-9A-Fa-f]+)$') {
        try { $availableInt = [Convert]::ToInt32($matches[1], 16) } catch { $availableInt = 0 }
    }

    # SECONDARY: state machine on UEFICA2023Status
    switch ($status) {

        'Updated' {
            if ($capable -eq '0x2' -and $noError) {
                # Fully applied and confirmed
                Write-Host "COMPLIANT: Registry confirms Secure Boot CA 2023 update applied (Status=Updated, Capable=0x2, Error=none)."
                return $true
            } else {
                # Updated but Capable value is unexpected, or an error is recorded
                Write-Warning "NON-COMPLIANT: Unexpected state - UEFICA2023Status=Updated but Capable='$capable' (expected 0x2), Error='$errCode', ErrorEvent='$errEvent'. Device requires manual investigation."
                return $false
            }
        }

        'InProgress' {
            # Stuck at 0x4104: bit 0x0004 (KEK deployment) not clearing after restarts indicates
            # the OEM has not signed the new KEK 2K CA 2023 with their Platform Key.
            if (($availableInt -band 0x0004) -ne 0 -and -not $noError) {
                Write-Warning "INVESTIGATE (KEK blocked): Status=InProgress, AvailableUpdates=$availableStr - bit 0x0004 (KEK deployment) has not cleared after restarts."
                Write-Warning "  This typically means the OEM has not signed KEK 2K CA 2023 with their Platform Key."
                Write-Warning "  Error Code : $errCode  |  Error Event : $errEvent"
                Write-Warning "  Resolution : Apply the latest OEM firmware/BIOS update for this device, then restart."
                Write-Warning "  Treatment  : Reported as Compliant - remediation cannot fix an OEM KEK signing gap."
                # Still compliant — no script action can resolve an OEM KEK signing gap.
                return $true
            }
            # Distinguish reboot-pending (bit 0x4100 set) from general in-progress
            if (($availableInt -band 0x4100) -eq 0x4100) {
                Write-Host "COMPLIANT (Reboot pending): Boot Manager update stage is complete and waiting for a reboot (Status=InProgress, AvailableUpdates=$availableStr). Reboot the device to finalise."
            } else {
                Write-Host "COMPLIANT (In progress): Windows is actively applying the Secure Boot CA 2023 update (Status=InProgress, AvailableUpdates=$availableStr). No action required."
            }
            return $true
        }

        'NotStarted' {
            # If trigger is already set to the full target value, the update is queued —
            # do not re-trigger; treat as compliant/waiting to avoid redundant writes.
            if ($availableInt -ne 0 -and ($availableInt -band $AvailableUpdatesValue) -eq $AvailableUpdatesValue) {
                Write-Host "COMPLIANT (Pending task): Registry trigger already set to target (AvailableUpdates=$availableStr). Waiting for Windows scheduled task or reboot to apply the update."
                return $true
            }
            # OS patch level may explain why the update has not started
            if ($Diagnostics['OSPatchCompliant'] -eq $false) {
                Write-Warning "NON-COMPLIANT: OS patch level is insufficient - $($Diagnostics['OSMinPatchNeeded']). Install the required Windows update before Secure Boot CA 2023 can be applied."
                return $false
            }
            Write-Warning "NON-COMPLIANT: Update not started (Status=NotStarted, AvailableUpdates=$availableStr). Remediation will set the registry trigger and start the update task."
            return $false
        }

        '(not set)' {
            # UEFICA2023Status key does not exist yet — device has not processed the update at all
            if ($Diagnostics['OSPatchCompliant'] -eq $false) {
                Write-Warning "NON-COMPLIANT: OS patch level is insufficient - $($Diagnostics['OSMinPatchNeeded']). Install the required Windows update before Secure Boot CA 2023 can be applied."
                return $false
            }
            Write-Warning "NON-COMPLIANT: UEFICA2023Status registry key is not present. The device has not yet received or processed the Secure Boot CA 2023 update."
            return $false
        }

        'Failed' {
            Write-Warning "NON-COMPLIANT: UEFICA2023Status=Failed - the Windows Secure Boot certificate update process encountered an error."
            Write-Warning "  Error Code     : $errCode"
            Write-Warning "  Error Event ID : $errEvent (check Windows System event log for details)"
            Write-Warning "  Capable        : $capable"
            Write-Warning "  Action needed  : Review UEFICA2023Error and the System event log."
            Write-Warning "                   An OEM firmware/BIOS update or manual intervention may be required."
            return $false
        }

        default {
            # Status value is set but does not match any known state
            Write-Warning "NON-COMPLIANT: Unknown UEFICA2023Status value '$status' (Capable='$capable', Error='$errCode', ErrorEvent='$errEvent'). Manual investigation is required."
            return $false
        }
    }
}

function Invoke-Remediation {
    [CmdletBinding(SupportsShouldProcess = $true)]
    <#
    .SYNOPSIS
        Sets the registry trigger and starts the Windows scheduled task to apply the
        Secure Boot CA 2023 certificate update.
    .DESCRIPTION
        Step 1: Ensures the registry key path exists, then sets AvailableUpdates = 0x5944.
        Step 2: Attempts to start the scheduled task \Microsoft\Windows\PI\Secure-Boot-Update.
        Does NOT directly inject certificates — uses only Windows' own built-in mechanism.
        Skips remediation if the device is on legacy BIOS, Secure Boot is disabled, or is a VM.
    .OUTPUTS
        [bool] $true = remediation steps were executed, $false = skipped or failed
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$Diagnostics
    )

    # Safety checks before making any changes
    if ($Diagnostics['SecureBootEnabled'] -notmatch 'Enabled') {
        Write-Warning "Remediation skipped: Secure Boot is not enabled on this device."
        return $false
    }

    if ($Diagnostics['FirmwareType'] -ne 'UEFI') {
        Write-Warning "Remediation skipped: Device is using legacy BIOS/non-UEFI firmware. Cannot apply Secure Boot CA 2023."
        return $false
    }

    if ($Diagnostics['HWIsVM'] -eq 'Yes') {
        $hwMake  = $Diagnostics['HWMake']
        $hwModel = $Diagnostics['HWModel']
        if ($hwMake -imatch 'Microsoft' -and $hwModel -imatch 'Virtual') {
            Write-Host "Remediation skipped (not applicable): Hyper-V virtual machine detected ($hwMake $hwModel)."
            Write-Host "  Known issue : KEK certificate updates fail on Hyper-V VMs with error 800703e6."
            Write-Host "               Status stays 'InProgress' indefinitely on affected Hyper-V VMs."
            Write-Host "  Action      : Apply Secure Boot CA 2023 updates on the Hyper-V host, not the VM."
        } elseif ($hwMake -imatch 'VMware' -or $hwModel -imatch 'VMware') {
            Write-Host "Remediation skipped (not applicable): VMware virtual machine detected ($hwMake $hwModel)."
            Write-Host "  Known issue : KEK updates fail on VMware VMs by default."
            Write-Host "  Workaround  : Set 'uefi.allowAuthBypass=TRUE' in VM advanced settings"
            Write-Host "               for manual UEFI enrollment on the VMware ESXi host."
        } else {
            Write-Host "Remediation skipped (not applicable): Virtual machine detected ($hwMake $hwModel)."
            Write-Host "  Secure Boot CA 2023 updates are not applicable to VMs."
            Write-Host "  Apply the update on the hypervisor host instead."
        }
        return $true
    }

    # ---- MDM management guard ----
    # If the Intune Settings Catalog policies are active (MicrosoftUpdateManagedOptIn=1),
    # writing AvailableUpdates here would conflict with the MDM-managed value.
    # MDM policy always wins on the next refresh cycle, creating a write loop.
    # Safe action: start the scheduled task only (complementary, not conflicting).
    if ($Diagnostics['MDMManagesSecureBoot'] -eq $true) {
        Write-Host 'MDM MANAGED: Intune Settings Catalog is managing Secure Boot CA 2023 updates.'
        Write-Host '  Detected policy : Configure Microsoft Update Managed Opt In = Enabled'
        Write-Host '  Skipping        : AvailableUpdates registry write (controlled by MDM — do not overwrite)'
        Write-Host '  Reason          : The Settings Catalog policy [Enable Secureboot Certificate Updates]'
        Write-Host '                    owns this trigger. Overwriting it would conflict with MDM management.'
        try {
            $task = Get-ScheduledTask -TaskPath $RemediateTaskPath -TaskName $RemediateTaskName -ErrorAction SilentlyContinue
            if ($task) {
                if ($PSCmdlet.ShouldProcess("$RemediateTaskPath$RemediateTaskName", 'Start Scheduled Task (MDM-managed mode)')) {
                    Start-ScheduledTask -TaskPath $RemediateTaskPath -TaskName $RemediateTaskName -ErrorAction SilentlyContinue
                    Write-Host "  Task started    : $RemediateTaskPath$RemediateTaskName (accelerates MDM-managed update)"
                    Write-Host '  Note            : A system reboot may be required to complete the certificate deployment.'
                }
            } else {
                Write-Host "  Task not found  : $RemediateTaskPath$RemediateTaskName - MDM policy will apply the update on its own schedule."
            }
        } catch {
            Write-Verbose "Could not start scheduled task in MDM-managed mode: $($_.Exception.Message)"
        }
        return $true
    }

    $success = $true

    # ---- Step 1: Set registry trigger ----
    try {
        if (-not (Test-Path $RemediateRegPath)) {
            New-Item -Path $RemediateRegPath -Force | Out-Null
            Write-Host "Created registry path: $RemediateRegPath"
        }

        $currentValue = Get-RegistryValues -Path $RemediateRegPath -Key $RemediateRegKey

        if ($currentValue -ne $AvailableUpdatesValue) {
            if ($PSCmdlet.ShouldProcess("$RemediateRegPath\$RemediateRegKey", "Set DWORD to 0x$($AvailableUpdatesValue.ToString('X4'))")) {
                Set-ItemProperty -Path $RemediateRegPath -Name $RemediateRegKey `
                    -Value $AvailableUpdatesValue -Type DWord -Force -ErrorAction Stop
                $prevDisplay = if ($null -ne $currentValue) { '0x{0:X}' -f $currentValue } else { '(not set)' }
                Write-Host ("Registry trigger set: $RemediateRegKey = 0x{0:X4} (previous: {1})" -f $AvailableUpdatesValue, $prevDisplay)
            }
        } else {
            Write-Host ("Registry trigger already at target: $RemediateRegKey = 0x{0:X4}. No change needed." -f $AvailableUpdatesValue)
        }
    } catch {
        Write-Error "Failed to set registry trigger '$RemediateRegKey': $($_.Exception.Message)"
        $success = $false
    }

    # ---- Step 2: Start the Windows Secure Boot update scheduled task ----
    try {
        $task = Get-ScheduledTask -TaskPath $RemediateTaskPath -TaskName $RemediateTaskName -ErrorAction SilentlyContinue
        if ($task) {
            if ($PSCmdlet.ShouldProcess("$RemediateTaskPath$RemediateTaskName", 'Start Scheduled Task')) {
                Start-ScheduledTask -TaskPath $RemediateTaskPath -TaskName $RemediateTaskName -ErrorAction Stop
                Write-Host "Scheduled task started: $RemediateTaskPath$RemediateTaskName"
                Write-Host 'A system reboot may be required to complete the Secure Boot certificate deployment.'
            }
        } else {
            Write-Warning "Scheduled task '$RemediateTaskPath$RemediateTaskName' not found on this device. The update will apply automatically during the next Windows Update cycle or reboot."
        }
    } catch {
        Write-Warning "Could not start scheduled task '$RemediateTaskPath$RemediateTaskName': $($_.Exception.Message). The update trigger is set and will apply on the next reboot."
        # This is a warning, not a hard failure — the registry trigger is the primary mechanism
    }

    return $success
}

#endregion

#region ---[Script Execution]---

$exitCode      = 0
$finalStatus   = 'Unknown'
$diagnostics   = $null
$isCompliant   = $false
$wasRemediated = $false

try {
    Invoke-ScriptLog -Mode Start -Name $ScriptName -LogPath $LogPath

    # Mutual exclusion guard — both switches cannot be specified simultaneously
    if ($DetectOnly -and $RemediateOnly) {
        throw '-DetectOnly and -RemediateOnly cannot both be specified. Use one switch or omit both for Auto mode (detect then remediate if needed).'
    }

    Write-Host '=========================================================='
    Write-Host "  $ScriptName  v$ScriptVersion"
    Write-Host "  Mode      : $Mode"
    Write-Host "  Started   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "  Log path  : $LogPath"
    Write-Host '=========================================================='

    # ---- Prerequisites ----
    $prereqOk = Confirm-Prerequisites
    if (-not $prereqOk) {
        Write-Error 'Prerequisites not met. Script cannot continue.'
        $finalStatus = 'Prerequisites not met'
        $exitCode    = 1
    } else {

        # ---- Diagnostics ----
        Write-Host ''
        Write-Host '--- Collecting system diagnostics ---'
        $diagnostics = Get-SecureBootDiagnostics -RegistryKeys $registryKeysStatus -OSVersions $OSversions

        # ---- Detection ----
        Write-Host ''
        Write-Host '--- Detection ---'
        $isCompliant = Invoke-Detection -Diagnostics $diagnostics

        # ---- Remediation ----
        if (-not $isCompliant -and $Mode -ne 'DetectOnly') {
            Write-Host ''
            Write-Host '--- Remediation ---'
            $wasRemediated = Invoke-Remediation -Diagnostics $diagnostics

            if ($wasRemediated) {
                $finalStatus = if ($diagnostics['HWIsVM'] -eq 'Yes') {
                    'Remediation not applicable - virtual machine (update must be applied on hypervisor host)'
                } else {
                    'Remediated - reboot may be required'
                }
                $exitCode    = 0
            } else {
                $finalStatus = 'Remediation skipped or failed - manual review required'
                $exitCode    = 1
            }

        } elseif ($isCompliant) {
            $finalStatus = 'Compliant - no action required'
            $exitCode    = 0
        } else {
            # DetectOnly + non-compliant
            $finalStatus = 'Non-Compliant - remediation not attempted (DetectOnly mode)'
            $exitCode    = 1
        }
    }

} catch {
    Write-Error "Unhandled script error: $($_.Exception.Message)"
    $finalStatus = 'Script error'
    $exitCode    = 1
} finally {
    # ---- Diagnostics summary ----
    if ($diagnostics) {
        Write-Host ''
        Write-Host '--- Diagnostics Summary ---'
        foreach ($key in $diagnostics.Keys) {
            Write-Host ('  {0,-32} = {1}' -f $key, $diagnostics[$key])
        }
    }

    Write-Host ''
    Write-Host '=========================================================='
    Write-Host "  Final Status  : $finalStatus"
    Write-Host "  Compliant     : $isCompliant"
    Write-Host "  Remediated    : $wasRemediated"
    Write-Host "  Completed     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host '=========================================================='

    # ---- Windows Event Log entry ----
    try {
        $evtId   = if ($exitCode -eq 0) { 1000 } else { 1001 }
        $evtType = if ($exitCode -eq 0) { 'Information' } else { 'Warning' }
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource($EventSource, 'Application')
        }
        Write-EventLog -LogName Application -Source $EventSource -EventId $evtId -EntryType $evtType `
            -Message "$ScriptName v$ScriptVersion`nMode       : $Mode`nStatus     : $finalStatus`nCompliant  : $isCompliant`nRemediated : $wasRemediated`nExit Code  : $exitCode"
        Write-Host "Event log entry written (Source: $EventSource, EventId: $evtId)"
    } catch {
        # Non-fatal: event log write failure should not affect the script result
    }

    # ---- Flush log to disk ----
    Invoke-ScriptLog -Mode Stop -Name $ScriptName -LogPath $LogPath | Out-Null
    Microsoft.PowerShell.Utility\Write-Host "Log saved to: $(Join-Path $LogPath "$ScriptName.log")"

    exit $exitCode
}

#endregion
