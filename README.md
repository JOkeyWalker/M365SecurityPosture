# M365 Security Posture Report

A **read-only** PowerShell script that audits the security configuration of a Microsoft 365 tenant and produces a color-coded console report plus a self-contained, SOC-style HTML report.

It covers **Microsoft Entra ID**, **Exchange Online**, **Microsoft Defender for Office 365 (EOP/MDO)** and **Intune**, and it starts with **licensing**, so you know which security features your tenant can actually use before you look at any settings.

> **Read-only by design.** Every call is a `Get-*` cmdlet or an HTTP `GET`. The script never changes tenant settings.

---

## Features

- **Licensing first**: lists SKUs (purchased vs. assigned) and shows which security capabilities your licenses unlock (Conditional Access, Identity Protection, PIM, Defender for Office 365 P1/P2, Defender for Endpoint, Intune).
- **MFA enforcement beyond Conditional Access**: Security Defaults, per-user (legacy) MFA, MFA registration counts, and an "MFA enforcement map" of every layer that can force MFA.
- **Conditional Access in detail**: every policy shows users and groups included/excluded (with group member counts), roles, apps, named locations (IP ranges/countries), platforms, client apps, risk levels, device filters, grant controls and session controls.
- **Admin role review**: active assignments for 14 privileged roles, with a Global Administrator count check.
- **Entra tenant defaults**: user consent to apps, app registration, tenant creation, guest access, guest invitations, authentication methods and more.
- **Intune status**: license vs. actual service state, enrolled devices, compliance, policies, and a cross-check against Conditional Access policies that require compliant devices.
- **SharePoint & OneDrive**: legacy (non-modern) authentication and the external sharing level.
- **Exchange Online**: auditing, SMTP AUTH, POP/IMAP, forwarding, external sender identification (native tag or transport rule), transport rules that bypass spam filtering (with their conditions), inbound connectors (TLS, IP/certificate restriction, Enhanced Filtering), DKIM/SPF/DMARC.
- **Defender (EOP/MDO)**: preset security policies, anti-phish (spoof/DMARC actions, safety tips, impersonation), anti-spam (actions, quarantine policy, retention, ZAP), anti-malware, quarantine policies, connection filter, Tenant Allow/Block List (allowed spoofed senders and allow entries), Advanced Delivery overrides, Safe Links, Safe Attachments.
- **Conditional Access extras**: registration of security info limited to trusted locations or compliant devices, trusted named locations (flags overly broad ranges), country-based policy, sign-in frequency.
- **Quiet console**: the terminal shows warnings, failures and license gaps only. Passing and informational checks are counted, and the HTML report has everything.
- **Configuration snapshot** (`-ExportConfig`): a JSON copy of the current policy settings, handy as "before" documentation for rollback.
- **Affected objects listed**: checks that report a count (for example "4 users") include an expandable list of the users or objects affected.
- **Summary and HTML report link at the top** of the console results, followed by the detailed output.

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | Windows PowerShell 5.1 or PowerShell 7+ |
| Modules | `ExchangeOnlineManagement`, `Microsoft.Graph.Authentication` |
| Entra roles | **Global Reader** + **Security Reader** (read-only) |
| Graph scopes | Requested at sign-in, all read-only (see below) |
| PDF button (optional) | Microsoft Edge or Google Chrome installed (used in the background to create the PDF) |

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Microsoft Graph permissions requested (read-only)

`Policy.Read.All`, `Directory.Read.All`, `Organization.Read.All`, `RoleManagement.Read.Directory`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementServiceConfig.Read.All`, `DeviceManagementApps.Read.All`, `SharePointTenantSettings.Read.All`

Some of these may require admin consent the first time you run the script.

---

## Usage

```powershell
# Standard run
.\M365SecurityPosture.ps1

# Also scan every mailbox for forwarding and audit bypass (slower on large tenants)
.\M365SecurityPosture.ps1 -ScanMailboxes

# Save the HTML report and CSV files to a specific folder
.\M365SecurityPosture.ps1 -ExportPath C:\Reports

# Print every check in the console (default shows problems only)
.\M365SecurityPosture.ps1 -Detailed

# Save a JSON copy of the current settings (documentation / rollback reference)
.\M365SecurityPosture.ps1 -ExportConfig

# Unattended: open the report automatically, no prompts
.\M365SecurityPosture.ps1 -OpenReport -NoPrompt
```

The script connects to **Exchange Online first**, then **Microsoft Graph**, then collects all data. Sign-in prompts appear first, then the results are displayed.

### Parameters

| Parameter | Description |
|---|---|
| `-ScanMailboxes` | Also scan all mailboxes for external forwarding and audit-bypass accounts. |
| `-SkipDns` | Skip public DNS lookups for SPF and DMARC. |
| `-SkipPerUserMfa` | Skip the per-user (legacy) MFA state scan. |
| `-Detailed` | Print every check in the console, including passing and informational ones (default: warnings, failures and license gaps only). |
| `-ExportConfig` | Also save a JSON snapshot of the current policy settings (Exchange, Defender, Entra, Conditional Access, SharePoint). Saved next to the HTML report. |
| `-MaxUsers <int>` | Maximum number of users checked for per-user MFA state (default `1000`). |
| `-ExportPath <folder>` | Folder for the HTML report and CSV files. Default for the HTML report: your Windows **Downloads** folder. |
| `-NoHtml` | Do not generate the HTML report. |
| `-NoPdf` | Do not create the PDF embedded in the HTML report (the button then uses the print dialog). |
| `-OpenReport` | Open the HTML report in your browser when finished. |
| `-NoPrompt` | Never ask whether to open the report (for unattended runs). |

---

## Output

### Console

Results are shown in this order:

1. **Summary**: tenant name and counts for Failing, Warnings, Blocked by licensing, Passing, Informational and Could not read
2. **HTML report link**: clickable `file:///` link and the file path
3. **Fix first** and **Licensing gaps** lists
4. **Detailed results**: sections 1 to 7. By default only problems are listed; each section ends with a count of the passing / informational checks left out (use `-Detailed` to list them).

| Section | Content |
|---|---|
| 1 | Tenant and licensing |
| 2 | MFA enforcement (Security Defaults, per-user MFA, registration, enforcement map) |
| 3 | Conditional Access (overview table + per-policy details) |
| 4 | Entra ID and SharePoint settings, privileged roles |
| 5 | Intune |
| 6 | Exchange Online |
| 7 | Microsoft Defender (EOP / MDO) |

### Status legend

| Status | Meaning |
|---|---|
| `PASS` | Meets the baseline |
| `WARN` | Weak or risky setting |
| `FAIL` | Fix first |
| `INFO` | Informational |
| `NOLIC` | The feature needs a license the tenant does not have |
| `ERROR` | The setting could not be read (usually a permission issue) |

### HTML report

Every run also creates a self-contained, dark-themed HTML report (no external resources; nothing leaves your machine) in your **Downloads** folder, with a **Download PDF** button. A static example with fictional data is included as `Sample-M365-Security-Report-PREVIEW.html`.

### CSV (only with `-ExportPath`)

- `M365-Findings-<timestamp>.csv`, including an `AffectedItems` column
- `M365-Licensing-<timestamp>.csv`
- `M365-FeatureMatrix-<timestamp>.csv`

With `-ExportConfig` a `M365-ConfigSnapshot-<tenant>-<timestamp>.json` file is also written.

---

## Limitations

- Admin roles show **active assignments only**. PIM-eligible assignments are not included.
- Legacy MFA service settings (trusted IPs, "remember MFA") are not exposed by Microsoft Graph, so the report flags them as a manual check.
- Defender for Endpoint and Defender for Cloud Apps device policies are out of scope (licensing is reported, policies are not).
- Only the default policies and the preset rules are graded for anti-spam, anti-phish and anti-malware, not every custom policy assignment.
- Some thresholds (bulk threshold 7, quarantine retention 15 days) are baseline values near the top of the script (`$Baseline`); adjust them to your own standard.
- Advanced Spam Filter (ASF) options are shown for information only; Microsoft describes them as aggressive and does not enable them in the Standard or Strict presets.
- Some checks use Microsoft Graph **beta** endpoints (per-user MFA state, Intune settings catalog). Microsoft may change these.
- If a setting cannot be read, the check shows `ERROR` and the script continues.

---

## Safety and disclaimer

- The script only reads configuration; it does not create, change or delete anything.
- Review the code and test in a non-production tenant before running it against production.
- Findings are guidance based on Microsoft and CISA-style recommendations. They are not a substitute for a formal security assessment or for your organization's own policies.

