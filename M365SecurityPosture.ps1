#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only security posture report for Microsoft Entra ID, Exchange Online and
    Microsoft Defender for Office 365 (EOP / MDO) - LICENSING FIRST.

.DESCRIPTION
    1. Connects to Exchange Online, then Microsoft Graph (read-only scopes).
    2. Reports tenant licensing and which security features that licensing unlocks.
    3. Dumps current settings for Entra ID, Exchange Online and Defender policies and
       grades each against common-flaw / secure-baseline guidance
       (Microsoft, CISA SCuBA, CIS-style recommendations).
    4. Shows the SUMMARY and the HTML REPORT LINK first, followed by the detailed results
       (output is collected during the run and replayed in that order).

    NOTHING IS CHANGED. Every call is a Get-* / HTTP GET.

.PARAMETER ScanMailboxes
    Also scans every mailbox for external forwarding and audit-bypass. Slow on big tenants.

.PARAMETER SkipDns
    Skip the public DNS lookups for SPF / DMARC.

.PARAMETER SkipPerUserMfa
    Skip the per-user (legacy) MFA state scan.

.PARAMETER MaxUsers
    Max users to check for per-user MFA state (default 1000). The scan uses Graph batching.

.PARAMETER Detailed
    Print every check in the console (default: only warnings, failures and license gaps; the HTML report always has everything).

.PARAMETER ExportConfig
    Also save a JSON snapshot of the current policy settings (useful as "before" documentation for rollback).

.PARAMETER NoHtml
    Do not generate the HTML report.

.PARAMETER NoPdf
    Do not create the PDF that the report's Download PDF button saves (the PDF is made automatically with headless Edge or Chrome).

.PARAMETER OpenReport
    Open the HTML report in the default browser when finished (otherwise you are asked).

.PARAMETER NoPrompt
    Never ask whether to open the HTML report (for unattended runs).

.PARAMETER ExportPath
    Optional folder for the HTML report and CSV files. Default: your Windows Downloads folder (HTML only).

.NOTES
    Modules : ExchangeOnlineManagement, Microsoft.Graph.Authentication
    Roles   : Global Reader + Security Reader is enough (read-only).
    Graph   : All READ-ONLY scopes: Policy.Read.All, Directory.Read.All, Organization.Read.All,
              RoleManagement.Read.Directory, User.Read.All, UserAuthenticationMethod.Read.All,
              AuditLog.Read.All, DeviceManagementManagedDevices.Read.All,
              DeviceManagementConfiguration.Read.All, DeviceManagementServiceConfig.Read.All,
              DeviceManagementApps.Read.All, SharePointTenantSettings.Read.All

.EXAMPLE
    .\M365SecurityPosture.ps1
.EXAMPLE
    .\M365SecurityPosture.ps1 -ScanMailboxes -ExportPath C:\Reports
#>
[CmdletBinding()]
param(
    [switch]$ScanMailboxes,
    [switch]$SkipDns,
    [switch]$SkipPerUserMfa,
    [switch]$Detailed,
    [switch]$ExportConfig,
    [switch]$NoHtml,
    [switch]$NoPdf,
    [switch]$OpenReport,
    [switch]$NoPrompt,
    [int]$MaxUsers = 1000,
    [string]$ExportPath
)

$ErrorActionPreference = 'Stop'
$script:Detailed    = [bool]$Detailed
$script:Quiet       = $false
$script:HiddenCount = 0
$script:CurGroup    = ''
$script:PendingSub  = $null

# Baseline values used by some checks - adjust to your own standard.
$Baseline = @{ BulkThreshold = 7; QuarantineRetentionDays = 15 }

# ----------------------------------------------------------------------------------------
#  Output buffering: all detailed output is collected first, then replayed AFTER the
#  summary + HTML link so the most important information is at the TOP of the results.
# ----------------------------------------------------------------------------------------
$script:Buffering = $false
$script:Buf       = [System.Collections.Generic.List[object]]::new()

function Write-Host {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromRemainingArguments = $true)][object[]]$Object,
        [System.ConsoleColor]$ForegroundColor,
        [System.ConsoleColor]$BackgroundColor,
        [switch]$NoNewline
    )
    if ($script:Quiet) { return }
    $text = if ($null -eq $Object) { '' } else { (@($Object) | ForEach-Object { "$_" }) -join ' ' }
    $fg = if ($PSBoundParameters.ContainsKey('ForegroundColor')) { "$ForegroundColor" } else { $null }
    $bg = if ($PSBoundParameters.ContainsKey('BackgroundColor')) { "$BackgroundColor" } else { $null }
    if ($script:Buffering) {
        $script:Buf.Add([pscustomobject]@{ T = $text; F = $fg; B = $bg; N = [bool]$NoNewline })
        return
    }
    $p = @{ Object = $text }
    if ($fg) { $p.ForegroundColor = $fg }
    if ($bg) { $p.BackgroundColor = $bg }
    if ($NoNewline) { $p.NoNewline = $true }
    Microsoft.PowerShell.Utility\Write-Host @p
}

function Show-Buffered {
    foreach ($e in $script:Buf) {
        $p = @{ Object = $e.T }
        if ($e.F) { $p.ForegroundColor = $e.F }
        if ($e.B) { $p.BackgroundColor = $e.B }
        if ($e.N) { $p.NoNewline = $true }
        Microsoft.PowerShell.Utility\Write-Host @p
    }
    $script:Buf.Clear()
}
$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:Line     = '=' * 92
$script:W        = 100
try { $w0 = $Host.UI.RawUI.WindowSize.Width; if ($w0 -gt 0) { $script:W = [Math]::Max(80, [Math]::Min(110, $w0 - 2)) } } catch { }
$script:Cards      = [System.Collections.Generic.List[object]]::new()
$script:CARows     = [System.Collections.Generic.List[object]]::new()
$script:RoleRows   = [System.Collections.Generic.List[object]]::new()
$script:CurrentCard = $null
$script:MfaStats   = $null
$script:MfaMap     = $null
$script:PerUser    = $null
$script:IntuneData = $null
$script:IntunePolicies = @()
$script:Tenant     = [pscustomobject]@{ Name = '(unknown)'; Domain = ''; Id = '' }

# ----------------------------------------------------------------------------------------
#  Output helpers
# ----------------------------------------------------------------------------------------
function Close-Section {
    # Says how many passing / informational checks were left out of the console for the section just finished.
    if (-not $script:Detailed -and $script:HiddenCount -gt 0) {
        Write-Host ("  + {0} passing / informational check(s) not listed here - see the HTML report, or run with -Detailed" -f $script:HiddenCount) -ForegroundColor DarkGray
    }
    $script:HiddenCount = 0
    $script:PendingSub  = $null
}

function Write-Section {
    param([string]$Number, [string]$Title)
    Close-Section
    $script:CurGroup = ''
    if ($script:Buffering) { Write-Progress -Id 1 -Activity 'Collecting security data (summary + HTML link are shown first when this finishes)' -Status $Title }
    $label = if ($Number) { "  {0}  |  {1}" -f $Number, $Title.ToUpper() } else { "  {0}" -f $Title.ToUpper() }
    Write-Host ''
    Write-Host (' ' * $script:W) -BackgroundColor DarkBlue
    Write-Host $label.PadRight($script:W) -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host (' ' * $script:W) -BackgroundColor DarkBlue
}

function Show-Sub {
    # Prints a pending sub-section heading (headings are lazy so empty groups never clutter the console).
    if ($script:PendingSub) {
        Write-Host ''
        Write-Host ("  >> {0} " -f $script:PendingSub).PadRight($script:W, '-') -ForegroundColor Cyan
        $script:PendingSub = $null
    }
}

function Write-SubSection {
    param([string]$Title, [switch]$Now)
    $script:CurGroup   = $Title
    $script:PendingSub = $Title
    if ($Now -or $script:Detailed) { Show-Sub }
}

function Add-Finding {
    param(
        [string]$Area,
        [string]$Check,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'NOLIC', 'ERROR')][string]$Status,
        [string]$Current,
        [string]$Guidance = '',
        [string]$License  = ''
    )
    $print = $script:Detailed -or ($Status -in 'WARN', 'FAIL', 'NOLIC', 'ERROR')
    $script:Findings.Add([pscustomobject]@{
        Area = $Area; Group = $script:CurGroup; Check = $Check; Status = $Status
        Current = $Current; Guidance = $Guidance; LicenseNeeded = $License; Items = @(); Printed = $print
    })
    if (-not $print) { $script:HiddenCount++; return }
    Show-Sub
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan'; NOLIC = 'Magenta'; ERROR = 'DarkGray' }[$Status]
    Write-Host ("  [{0,-5}] " -f $Status) -ForegroundColor $color -NoNewline
    Write-Host ("{0,-44}" -f $Check) -NoNewline
    Write-Host $Current -ForegroundColor Gray
    if ($Guidance -and $Status -in 'WARN', 'FAIL', 'NOLIC') {
        Write-Host ("          -> {0}" -f $Guidance) -ForegroundColor DarkGray
    }
}

function Set-LastFindingItems {
    # Attaches the affected users / objects to the finding that was just added.
    # HTML report + CSV always get the full list; the console shows only the first few (0 = none).
    param([string[]]$Items, [int]$Show = 5)
    $Items = @($Items | Where-Object { $_ })
    if (-not $Items) { return }
    $last = $script:Findings[$script:Findings.Count - 1]
    $last.Items = $Items
    if (-not $last.Printed -or $Show -le 0) { return }
    $Show = [Math]::Min($Show, $(if ($script:Detailed) { 25 } else { 5 }))
    $col = switch ($last.Status) { 'FAIL' { 'Red' } 'WARN' { 'Yellow' } default { 'Gray' } }
    foreach ($i in ($Items | Select-Object -First $Show)) { Write-Host ("            - {0}" -f $i) -ForegroundColor $col }
    if ($Items.Count -gt $Show) { Write-Host ("            ... +{0} more (full list in the HTML report and CSV)" -f ($Items.Count - $Show)) -ForegroundColor DarkGray }
}

function Invoke-Safe {
    param([string]$Area, [string]$Check, [scriptblock]$Block)
    try { & $Block }
    catch {
        $script:Quiet = $false
        $msg = ($_.Exception.Message -split "`n")[0]
        if ($msg.Length -gt 70) { $msg = $msg.Substring(0, 70) + '...' }
        Add-Finding -Area $Area -Check $Check -Status ERROR -Current "Could not read: $msg"
    }
}

function Get-GraphAll {
    param([string]$Uri)
    $items = @()
    while ($Uri) {
        $r = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        if ($r.PSObject.Properties['value']) { $items += $r.value } else { return $r }
        $Uri = $r.'@odata.nextLink'
    }
    return $items
}

function OnOff { param($v) if ($v -eq $true) { 'On' } elseif ($v -eq $false) { 'Off' } else { 'n/a' } }
function Get-RuleCondText {
    param($r)
    $p = @()
    if ($r.SenderDomainIs) { $p += 'sender domain: ' + (@($r.SenderDomainIs) -join ', ') }
    if ($r.From)           { $p += 'from: ' + (@($r.From) -join ', ') }
    if ($r.SenderIpRanges) { $p += 'IPs: ' + (@($r.SenderIpRanges) -join ', ') }
    if ($r.SenderDomainIs -and -not $r.SenderIpRanges) { $p += 'DOMAIN-ONLY - can be spoofed' }
    if ($p) { $p -join '; ' } else { 'no sender condition' }
}
function Format-Bool { param($v) if ($v -eq $true) { 'Enabled' } elseif ($v -eq $false) { 'Disabled' } else { "$v" } }

# ----------------------------------------------------------------------------------------
#  Conditional Access / name-resolution / display helpers
# ----------------------------------------------------------------------------------------
$script:IdCache   = @{}
$script:GrpCount  = @{}
$script:AppCache  = @{}
$script:RoleMap   = @{}
$script:LocMap    = @{}
$script:KnownApps = @{
    'All'                                  = 'ALL CLOUD APPS'
    'None'                                 = '(no apps)'
    'Office365'                            = 'Office 365 (app group)'
    'MicrosoftAdminPortals'                = 'Microsoft Admin Portals'
    '00000002-0000-0ff1-ce00-000000000000' = 'Exchange Online'
    '00000003-0000-0ff1-ce00-000000000000' = 'SharePoint Online'
    '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Azure Management (portal / ARM / CLI)'
    'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe' = 'Microsoft Teams'
    '0000000a-0000-0000-c000-000000000000' = 'Microsoft Intune'
}

function Get-DownloadsFolder {
    # Finds the user's real Downloads folder (works with redirected / network profile folders).
    $cands = @()
    $onWin = ($PSVersionTable.PSEdition -ne 'Core') -or [bool]$IsWindows
    if ($onWin) {
        # 1) Ask Windows for the Downloads known folder (honours folder redirection)
        try {
            if (-not ('KnownFolderNative' -as [type])) {
                Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KnownFolderNative {
    [DllImport("shell32.dll")]
    private static extern int SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);
    public static string Get(Guid id) {
        IntPtr p;
        if (SHGetKnownFolderPath(id, 0, IntPtr.Zero, out p) != 0) { return null; }
        try { return Marshal.PtrToStringUni(p); } finally { Marshal.FreeCoTaskMem(p); }
    }
}
'@
            }
            $cands += [KnownFolderNative]::Get([Guid]'374DE290-123F-4565-9164-39C4925E467B')
        } catch { }
        # 2) Registry (User Shell Folders)
        try {
            $v = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Stop).'{374DE290-123F-4565-9164-39C4925E467B}'
            if ($v) { $cands += [Environment]::ExpandEnvironmentVariables($v) }
        } catch { }
    }
    # 3) Conventional locations
    if ($HOME)             { $cands += (Join-Path $HOME 'Downloads') }
    if ($env:USERPROFILE)  { $cands += (Join-Path $env:USERPROFILE 'Downloads') }
    $docs = [Environment]::GetFolderPath('MyDocuments')
    if ($docs)             { $cands += (Join-Path $docs 'Downloads') }
    $cands = @($cands | Where-Object { $_ } | Select-Object -Unique)

    foreach ($c in $cands) { try { if (Test-Path -LiteralPath $c -PathType Container) { return $c } } catch { } }
    # None exists yet: create the first candidate whose parent folder exists
    foreach ($c in $cands) {
        try {
            $parent = Split-Path $c -Parent
            if ($parent -and (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $c -Force | Out-Null; return $c }
        } catch { }
    }
    if ($docs) { return $docs }
    return [IO.Path]::GetTempPath()
}

function Get-Arr { param($x) @($x | Where-Object { $null -ne $_ -and "$_" -ne '' }) }

function Cut { param([string]$s, [int]$n) if ($s.Length -gt $n) { $s.Substring(0, $n - 2) + '..' } else { $s } }

function Resolve-Ids {
    param([string[]]$Ids)
    $need = @($Ids | Where-Object { $_ -match '^[0-9a-fA-F-]{36}$' -and -not $script:IdCache.ContainsKey($_) } | Select-Object -Unique)
    for ($i = 0; $i -lt $need.Count; $i += 500) {
        $chunk = @($need[$i..([Math]::Min($i + 499, $need.Count - 1))])
        try {
            $body = @{ ids = $chunk } | ConvertTo-Json
            $r = Invoke-MgGraphRequest -Method POST -Uri 'v1.0/directoryObjects/getByIds' -Body $body -ContentType 'application/json' -OutputType PSObject
            foreach ($o in $r.value) {
                $type = ($o.'@odata.type' -replace '#microsoft.graph.', '')
                $nm   = if ($o.userPrincipalName) { $o.userPrincipalName } else { $o.displayName }
                $script:IdCache[$o.id] = [pscustomobject]@{ Name = $nm; Type = $type }
            }
        } catch { }
    }
}

function Format-Id {
    param([string]$Id)
    if (-not $script:IdCache.ContainsKey($Id)) { return "$Id (unresolved / deleted object)" }
    $o = $script:IdCache[$Id]
    if ($o.Type -eq 'group') {
        if (-not $script:GrpCount.ContainsKey($Id)) {
            try { $script:GrpCount[$Id] = [string](Invoke-MgGraphRequest -Method GET -Uri "v1.0/groups/$Id/members/`$count" -Headers @{ ConsistencyLevel = 'eventual' }) }
            catch { $script:GrpCount[$Id] = '?' }
        }
        return ("{0}  [group, {1} members]" -f $o.Name, $script:GrpCount[$Id])
    }
    if ($o.Type -eq 'user') { return $o.Name }
    return ("{0}  [{1}]" -f $o.Name, $o.Type)
}

function Get-RoleName {
    param($Id)
    if ($script:RoleMap.ContainsKey($Id)) { $script:RoleMap[$Id] } elseif ($Id -eq 'All') { 'All roles' } else { $Id }
}

function Get-AppName {
    param([string]$Id)
    if ($script:KnownApps.ContainsKey($Id)) { return $script:KnownApps[$Id] }
    if ($script:AppCache.ContainsKey($Id))  { return $script:AppCache[$Id] }
    $name = $Id
    try {
        $r = Invoke-MgGraphRequest -Method GET -Uri ("v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=displayName" -f $Id) -OutputType PSObject
        if ($r.value -and $r.value[0].displayName) { $name = $r.value[0].displayName }
    } catch { }
    $script:AppCache[$Id] = $name
    return $name
}

function Get-LocName {
    param([string]$Id)
    switch ($Id) {
        'All'        { return 'Any location' }
        'AllTrusted' { return 'All TRUSTED locations' }
        default      { if ($script:LocMap.ContainsKey($Id)) { return $script:LocMap[$Id] } else { return $Id } }
    }
}

function Write-CardLine {
    param([string]$Label, $Text, [string]$Color = 'Gray', [string]$LabelColor = 'White')
    $lines = @($Text)
    if ($script:CurrentCard) { $script:CurrentCard.Lines.Add([pscustomobject]@{ Label = $Label; Text = $lines; Color = $Color }) }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        Write-Host '  | ' -ForegroundColor DarkGray -NoNewline
        Write-Host ("{0,-18}" -f $(if ($i -eq 0) { $Label } else { '' })) -ForegroundColor $LabelColor -NoNewline
        Write-Host $lines[$i] -ForegroundColor $Color
    }
}

function Write-Bar {
    # Bar shows the proportion; the text on the right shows real numbers (e.g. 17 / 31).
    param([double]$Pct, [string]$Prefix = '', [int]$Width = 30, [string]$Detail = '', [switch]$Invert)
    $fill = [int][Math]::Round($Width * $Pct / 100)
    if ($Invert) { $col = if ($Pct -le 10) { 'Green' } elseif ($Pct -le 40) { 'Yellow' } else { 'Red' } }
    else         { $col = if ($Pct -ge 90) { 'Green' } elseif ($Pct -ge 60) { 'Yellow' } else { 'Red' } }
    Write-Host ("    {0,-41} " -f $Prefix) -NoNewline
    Write-Host ('#' * $fill) -ForegroundColor $col -NoNewline
    Write-Host ('-' * ($Width - $fill)) -ForegroundColor DarkGray -NoNewline
    if ($Detail) { Write-Host (" {0,9}" -f $Detail) -ForegroundColor $col } else { Write-Host (" {0,5:N1}%" -f $Pct) -ForegroundColor $col }
}

function Test-RequiresMfa {
    param($p)
    [bool]($p.grantControls -and ($p.grantControls.builtInControls -contains 'mfa' -or $p.grantControls.authenticationStrength))
}

function Get-CAUsersShort {
    param($u)
    $inc = Get-Arr $u.includeUsers
    $txt = if ($inc -contains 'All') { 'All users' }
           else {
               $n = @($inc | Where-Object { $_ -notin 'None', 'GuestsOrExternalUsers' }).Count + @(Get-Arr $u.includeGroups).Count
               $parts = @()
               if ($n) { $parts += "$n user/group" }
               if (@(Get-Arr $u.includeRoles).Count) { $parts += "$(@(Get-Arr $u.includeRoles).Count) roles" }
               if ($inc -contains 'GuestsOrExternalUsers' -or $u.includeGuestsOrExternalUsers) { $parts += 'guests' }
               if ($parts) { $parts -join ', ' } else { '(none)' }
           }
    $ex = @(Get-Arr $u.excludeUsers).Count + @(Get-Arr $u.excludeGroups).Count + @(Get-Arr $u.excludeRoles).Count
    if ($ex) { $txt += " (-$ex excl)" }
    $txt
}

function Get-CAGrantShort {
    param($p)
    $g = $p.grantControls
    if (-not $g) { return 'session only' }
    $short = @{ mfa = 'MFA'; compliantDevice = 'Compliant'; domainJoinedDevice = 'Hybrid-joined'; approvedApplication = 'ApprovedApp'; compliantApplication = 'AppProtection'; passwordChange = 'PwdChange'; block = 'BLOCK' }
    $c = @(); foreach ($b in (Get-Arr $g.builtInControls)) { $c += $(if ($short[$b]) { $short[$b] } else { $b }) }
    if ($g.authenticationStrength) { $c += ('AuthStrength:' + $g.authenticationStrength.displayName) }
    if (-not $c) { return '(none)' }
    $c -join $(if ($g.operator -eq 'OR') { ' OR ' } else { ' + ' })
}

function Show-CAPolicy {
    param($p)
    $c = $p.conditions; $u = $c.users; $a = $c.applications

    $stateTxt   = switch ($p.state) { 'enabled' { 'ON' } 'disabled' { 'OFF' } default { 'REPORT-ONLY' } }
    $stateColor = switch ($p.state) { 'enabled' { 'Green' } 'disabled' { 'DarkGray' } default { 'Yellow' } }
    $when = if ($p.modifiedDateTime) { ([datetime]$p.modifiedDateTime).ToString('yyyy-MM-dd') } elseif ($p.createdDateTime) { ([datetime]$p.createdDateTime).ToString('yyyy-MM-dd') } else { '?' }

    Write-Host ''
    Write-Host '  +-- ' -ForegroundColor DarkGray -NoNewline
    Write-Host ("[{0}]" -f $stateTxt) -ForegroundColor $stateColor -NoNewline
    Write-Host (" {0}" -f $p.displayName) -ForegroundColor White -NoNewline
    Write-Host ("    last changed {0}" -f $when) -ForegroundColor DarkGray
    $script:CurrentCard = [pscustomobject]@{ Name = $p.displayName; State = $stateTxt; When = $when; Lines = [System.Collections.Generic.List[object]]::new() }

    # ---- USERS -------------------------------------------------------------------------
    $in = @()
    foreach ($x in (Get-Arr $u.includeUsers)) {
        switch ($x) { 'All' { $in += 'ALL USERS' } 'None' { } 'GuestsOrExternalUsers' { $in += 'All guests / external users' } default { $in += (Format-Id $x) } }
    }
    foreach ($g in (Get-Arr $u.includeGroups)) { $in += (Format-Id $g) }
    foreach ($r in (Get-Arr $u.includeRoles))  { $in += ('Role: ' + (Get-RoleName $r)) }
    if ($u.includeGuestsOrExternalUsers) { $in += ('Guest/external types: ' + $u.includeGuestsOrExternalUsers.guestOrExternalUserTypes) }
    if (-not $in) { $in = @('(nobody)') }

    $out = @()
    foreach ($x in (Get-Arr $u.excludeUsers)) {
        switch ($x) { 'GuestsOrExternalUsers' { $out += 'All guests / external users' } default { $out += (Format-Id $x) } }
    }
    foreach ($g in (Get-Arr $u.excludeGroups)) { $out += (Format-Id $g) }
    foreach ($r in (Get-Arr $u.excludeRoles))  { $out += ('Role: ' + (Get-RoleName $r)) }
    if ($u.excludeGuestsOrExternalUsers) { $out += ('Guest/external types: ' + $u.excludeGuestsOrExternalUsers.guestOrExternalUserTypes) }

    Write-CardLine 'USERS INCLUDED'  $in 'Green' 'Green'
    if ($out) { Write-CardLine 'USERS EXCLUDED' $out 'Yellow' 'Yellow' } else { Write-CardLine 'USERS EXCLUDED' '(no exclusions)' 'DarkGray' 'DarkGray' }

    # ---- APPS --------------------------------------------------------------------------
    $appsIn = @()
    foreach ($x in (Get-Arr $a.includeApplications)) { $appsIn += (Get-AppName $x) }
    foreach ($x in (Get-Arr $a.includeUserActions)) {
        $appsIn += $(switch ($x) { 'urn:user:registersecurityinfo' { 'User action: Register security info (MFA/SSPR)' } 'urn:user:registerdevice' { 'User action: Register or join devices' } default { "User action: $x" } })
    }
    foreach ($x in (Get-Arr $a.includeAuthenticationContextClassReferences)) { $appsIn += "Authentication context: $x" }
    if (-not $appsIn) { $appsIn = @('(none)') }
    $appsOut = @(); foreach ($x in (Get-Arr $a.excludeApplications)) { $appsOut += (Get-AppName $x) }

    Write-CardLine 'APPS INCLUDED' $appsIn 'Green' 'Green'
    if ($appsOut) { Write-CardLine 'APPS EXCLUDED' $appsOut 'Yellow' 'Yellow' } else { Write-CardLine 'APPS EXCLUDED' '(no exclusions)' 'DarkGray' 'DarkGray' }

    # ---- LOCATIONS ---------------------------------------------------------------------
    if ($c.locations) {
        $li = @(); foreach ($x in (Get-Arr $c.locations.includeLocations)) { $li += (Get-LocName $x) }
        $lo = @(); foreach ($x in (Get-Arr $c.locations.excludeLocations)) { $lo += (Get-LocName $x) }
        Write-CardLine 'LOCATION INCLUDED' $(if ($li) { $li } else { 'Any location' }) 'Green' 'Green'
        if ($lo) { Write-CardLine 'LOCATION EXCLUDED' $lo 'Yellow' 'Yellow' } else { Write-CardLine 'LOCATION EXCLUDED' '(no exclusions)' 'DarkGray' 'DarkGray' }
    }
    else { Write-CardLine 'LOCATION' 'Any location (not used as a condition)' 'DarkGray' 'DarkGray' }

    # ---- OTHER CONDITIONS --------------------------------------------------------------
    $plat = @()
    if ($c.platforms) {
        if (Get-Arr $c.platforms.includePlatforms) { $plat += ('Include: ' + ((Get-Arr $c.platforms.includePlatforms) -join ', ')) }
        if (Get-Arr $c.platforms.excludePlatforms) { $plat += ('Exclude: ' + ((Get-Arr $c.platforms.excludePlatforms) -join ', ')) }
    }
    Write-CardLine 'PLATFORMS' $(if ($plat) { $plat } else { 'Any platform' }) $(if ($plat) { 'White' } else { 'DarkGray' }) 'DarkCyan'

    $cm = @{ browser = 'Browser'; mobileAppsAndDesktopClients = 'Mobile apps & desktop clients'; exchangeActiveSync = 'Exchange ActiveSync (legacy)'; other = 'Other / legacy clients' }
    $clients = @(); foreach ($x in (Get-Arr $c.clientAppTypes)) { $clients += $(if ($cm[$x]) { $cm[$x] } else { $x }) }
    if ($clients -contains 'Exchange ActiveSync (legacy)' -or $clients -contains 'Other / legacy clients') { $ccol = 'Red' } elseif ($c.clientAppTypes -contains 'all' -or -not $clients) { $ccol = 'DarkGray' } else { $ccol = 'White' }
    Write-CardLine 'CLIENT APPS' $(if ($clients -and $c.clientAppTypes -notcontains 'all') { $clients -join ' | ' } else { 'All client app types' }) $ccol 'DarkCyan'

    $risk = @()
    if (Get-Arr $c.signInRiskLevels) { $risk += ('Sign-in risk: ' + ((Get-Arr $c.signInRiskLevels) -join ', ')) }
    if (Get-Arr $c.userRiskLevels)   { $risk += ('User risk: ' + ((Get-Arr $c.userRiskLevels) -join ', ')) }
    Write-CardLine 'RISK' $(if ($risk) { $risk } else { 'Not used (requires Entra ID P2)' }) $(if ($risk) { 'Magenta' } else { 'DarkGray' }) 'DarkCyan'

    if ($c.devices -and $c.devices.deviceFilter) {
        Write-CardLine 'DEVICE FILTER' ("{0}: {1}" -f $c.devices.deviceFilter.mode, $c.devices.deviceFilter.rule) 'White' 'DarkCyan'
    }
    else { Write-CardLine 'DEVICE FILTER' 'None' 'DarkGray' 'DarkCyan' }

    # ---- GRANT / SESSION ---------------------------------------------------------------
    $g = $p.grantControls
    if (-not $g) { Write-CardLine 'GRANT' '(no grant controls - session controls only)' 'DarkGray' 'Cyan' }
    else {
        $names = @{ mfa = 'Require multifactor authentication'; compliantDevice = 'Require device to be marked compliant (Intune)'; domainJoinedDevice = 'Require hybrid Entra joined device'
                    approvedApplication = 'Require approved client app'; compliantApplication = 'Require app protection policy'; passwordChange = 'Require password change'; block = 'BLOCK ACCESS' }
        $ctl = @(); foreach ($b in (Get-Arr $g.builtInControls)) { $ctl += $(if ($names[$b]) { $names[$b] } else { $b }) }
        if ($g.authenticationStrength) { $ctl += ('Authentication strength: ' + $g.authenticationStrength.displayName) }
        foreach ($t in (Get-Arr $g.termsOfUse)) { $ctl += "Terms of use ($t)" }
        foreach ($t in (Get-Arr $g.customAuthenticationFactors)) { $ctl += "Custom control ($t)" }
        $lines = if ($ctl.Count -gt 1) { @($(if ($g.operator -eq 'OR') { 'Require ANY ONE of:' } else { 'Require ALL of:' })) + ($ctl | ForEach-Object { "  - $_" }) } else { $ctl }
        Write-CardLine 'GRANT' $lines $(if ($g.builtInControls -contains 'block') { 'Red' } else { 'Cyan' }) 'Cyan'
    }

    $s = $p.sessionControls; $sess = @()
    if ($s) {
        if ($s.signInFrequency -and $s.signInFrequency.isEnabled) {
            $sf = $s.signInFrequency
            $sess += $(if ($sf.frequencyInterval -eq 'everyTime') { 'Sign-in frequency: every time' } else { "Sign-in frequency: every $($sf.value) $($sf.type)" })
        }
        if ($s.persistentBrowser -and $s.persistentBrowser.isEnabled) { $sess += "Persistent browser session: $($s.persistentBrowser.mode)" }
        if ($s.applicationEnforcedRestrictions -and $s.applicationEnforcedRestrictions.isEnabled) { $sess += 'App-enforced restrictions' }
        if ($s.cloudAppSecurity -and $s.cloudAppSecurity.isEnabled) { $sess += "Defender for Cloud Apps: $($s.cloudAppSecurity.cloudAppSecurityType)" }
        if ($s.continuousAccessEvaluation) { $sess += "Continuous access evaluation: $($s.continuousAccessEvaluation.mode)" }
        if ($s.disableResilienceDefaults) { $sess += 'Resilience defaults DISABLED' }
    }
    Write-CardLine 'SESSION' $(if ($sess) { $sess } else { 'None' }) $(if ($sess) { 'Magenta' } else { 'DarkGray' }) 'Magenta'

    # ---- NOTES -------------------------------------------------------------------------
    $exclCount = @(Get-Arr $u.excludeUsers).Count + @(Get-Arr $u.excludeGroups).Count + @(Get-Arr $u.excludeRoles).Count
    $notes = @()
    if ($p.state -eq 'enabledForReportingButNotEnforced') { $notes += @{ T = 'Report-only: logs the impact but does NOT enforce anything.'; C = 'Yellow' } }
    if ($p.state -eq 'disabled') { $notes += @{ T = 'Policy is OFF - not protecting anything.'; C = 'DarkGray' } }
    if ($p.state -eq 'enabled' -and ($in -contains 'ALL USERS') -and $exclCount -eq 0) {
        $notes += @{ T = 'Targets ALL users with NO exclusions - no break-glass exemption (lockout risk).'; C = 'Yellow' }
    }
    elseif ($exclCount -gt 0) { $notes += @{ T = "$exclCount exclusion(s) - confirm each is intentional and reviewed (excluded users bypass this policy)."; C = 'Yellow' } }
    if ($p.displayName -like 'Microsoft-managed*') { $notes += @{ T = 'Microsoft-managed policy.'; C = 'Cyan' } }
    foreach ($n in $notes) { Write-CardLine 'NOTES' $n.T $n.C 'DarkYellow' }
    $script:Cards.Add($script:CurrentCard); $script:CurrentCard = $null
    Write-Host '  +' ('-' * ($script:W - 4)) -ForegroundColor DarkGray
}


# ----------------------------------------------------------------------------------------
#  HTML report builder (self-contained file, SOC-style dark theme)
# ----------------------------------------------------------------------------------------
function Find-HeadlessBrowser {
    # Looks for Microsoft Edge or Google Chrome (used only to turn the HTML report into a PDF).
    $c = @()
    $onWin = ($PSVersionTable.PSEdition -ne 'Core') -or [bool]$IsWindows
    if ($onWin) {
        foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)) {
            if ($root) {
                $c += (Join-Path $root 'Microsoft\Edge\Application\msedge.exe')
                $c += (Join-Path $root 'Google\Chrome\Application\chrome.exe')
            }
        }
    }
    else {
        $c += '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'
        $c += '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
        foreach ($n in 'microsoft-edge', 'google-chrome', 'chromium', 'chromium-browser') {
            $g = Get-Command $n -ErrorAction SilentlyContinue
            if ($g) { $c += $g.Source }
        }
    }
    foreach ($x in $c) { if ($x -and (Test-Path -LiteralPath $x)) { return $x } }
    return $null
}

function New-PdfFromHtml {
    # Renders the report (in "#pdf" mode = one continuous, fully expanded page) to a PDF with headless Edge / Chrome.
    param([string]$HtmlPath, [string]$PdfPath)
    $exe = Find-HeadlessBrowser
    if (-not $exe) { return $false }
    $onWin = ($PSVersionTable.PSEdition -ne 'Core') -or [bool]$IsWindows
    # render from a local temp copy (the report folder may be a network share)
    $tmpHtml = Join-Path ([IO.Path]::GetTempPath()) ('m365report-{0}.html' -f [guid]::NewGuid().ToString('N'))
    Copy-Item -LiteralPath $HtmlPath -Destination $tmpHtml -Force
    $uri = ([System.Uri]$tmpHtml).AbsoluteUri + '#pdf'
    try {
        foreach ($mode in '--headless=new', '--headless') {
            $prof = Join-Path ([IO.Path]::GetTempPath()) ('m365pdf-' + [guid]::NewGuid().ToString('N'))
            $out  = Join-Path ([IO.Path]::GetTempPath()) ('m365pdf-' + [guid]::NewGuid().ToString('N') + '.out')
            $err  = $out + '.err'
            $argList = @($mode, '--disable-gpu', '--no-first-run', '--no-pdf-header-footer', '--hide-scrollbars', '--window-size=1280,1000',
                         '--run-all-compositor-stages-before-draw', '--virtual-time-budget=20000',
                         "--user-data-dir=`"$prof`"", "--print-to-pdf=`"$PdfPath`"", "`"$uri`"") -join ' '
            try {
                $sp = @{ FilePath = $exe; ArgumentList = $argList; PassThru = $true; RedirectStandardOutput = $out; RedirectStandardError = $err }
                if ($onWin) { $sp.WindowStyle = 'Hidden' }
                $p = Start-Process @sp
                if (-not $p.WaitForExit(90000)) { try { $p.Kill() } catch { } }
            }
            catch { }
            finally { foreach ($t in $prof, $out, $err) { try { Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue } catch { } } }
            if ((Test-Path -LiteralPath $PdfPath) -and ((Get-Item -LiteralPath $PdfPath).Length -gt 2000)) { return $true }
        }
        return $false
    }
    finally { Remove-Item -LiteralPath $tmpHtml -Force -ErrorAction SilentlyContinue }
}

function Esc { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

function New-HtmlReport {
    param([string]$Path, [string]$PdfBase64 = '', [string]$PdfName = '')
    $sb = [System.Text.StringBuilder]::new()
    $inv = [Globalization.CultureInfo]::InvariantCulture
    function Emit { param([string]$t) [void]$sb.AppendLine($t) }

    function Emit-FindingTable {
        param($set)
        Emit '<table class="tbl chk"><thead><tr><th>Status</th><th>Check</th><th>Current setting</th><th>Recommendation</th><th>License</th></tr></thead><tbody>'
        $lastGroup = $null
        foreach ($r in $set) {
            if ($r.Group -and $r.Group -ne $lastGroup) { Emit ('<tr class="grp"><td colspan="5">{0}</td></tr>' -f (Esc $r.Group)); $lastGroup = $r.Group }
            $g = if ($r.Status -in 'WARN', 'FAIL', 'NOLIC') { $r.Guidance } else { '' }
            $cur = Esc $r.Current
            if (@($r.Items).Count) {
                $li  = (@($r.Items) | ForEach-Object { '<li>' + (Esc $_) + '</li>' }) -join ''
                $cur += ('<details class="mini"><summary>show all {0}</summary><ul class="mem">{1}</ul></details>' -f @($r.Items).Count, $li)
            }
            Emit ('<tr data-status="{0}"><td><span class="badge b-{0}">{1}</span></td><td>{2}</td><td>{3}</td><td class="muted">{4}</td><td class="muted">{5}</td></tr>' -f $r.Status.ToLower(), $r.Status, (Esc $r.Check), $cur, (Esc $g), (Esc $r.LicenseNeeded))
        }
        Emit '</tbody></table>'
    }

    function Emit-Findings {
        param([string[]]$Areas)
        $rows = @($script:Findings | Where-Object { $_.Area -in $Areas })
        if (-not $rows) { Emit '<p class="muted">No checks in this section.</p>'; return }
        $main = @($rows | Where-Object { $_.Status -notin 'PASS', 'INFO' })
        $rest = @($rows | Where-Object { $_.Status -in 'PASS', 'INFO' })
        if ($main.Count) { Emit-FindingTable $main } else { Emit '<p class="muted okmsg">No warnings, failures or license gaps in this section.</p>' }
        if ($rest.Count) {
            Emit ('<details class="passes"><summary>{0} passing / informational check(s)</summary>' -f $rest.Count)
            Emit-FindingTable $rest
            Emit '</details>'
        }
    }

    function Emit-Bar {
        param([double]$Pct, [string]$Label, [string]$Detail = '', [switch]$Invert)
        $cls = if ($Invert) { if ($Pct -le 10) { 'ok' } elseif ($Pct -le 40) { 'mid' } else { 'low' } } else { if ($Pct -ge 90) { 'ok' } elseif ($Pct -ge 60) { 'mid' } else { 'low' } }
        $p   = [string]::Format($inv, '{0:0.0}', $Pct)
        $txt = if ($Detail) { $Detail } else { "$p%" }
        Emit ('<div class="barrow"><span>{0}</span><div class="bar"><div class="fill {1}" style="width:{2}%"></div></div><b>{3}</b></div>' -f (Esc $Label), $cls, $p, (Esc $txt))
    }

    function Emit-Kpi {
        param([string]$Label, [string]$Value, [string]$Sub = '', [string]$Cls = '', [string]$Filter = '')
        $attr = if ($Filter) { ' data-f="' + $Filter + '" title="Click to filter checks"' } else { '' }
        $cc   = if ($Filter) { "$Cls click" } else { $Cls }
        Emit ('<div class="kpi {0}"{4}><div class="kl">{1}</div><div class="kv2">{2}</div><div class="ks">{3}</div></div>' -f $cc, (Esc $Label), (Esc $Value), (Esc $Sub), $attr)
    }

    $css = @'
:root{--bg:#04070d;--panel:#0b1324;--panel2:#101b33;--line:#1c2b4a;--text:#e8eef9;--muted:#8a9ab6;--blue:#3b82f6;--sky:#38bdf8;--navy:#1e3a8a;--fail:#ef4444;--warn:#f59e0b;--pass:#22c55e;--lic:#818cf8}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Arial,sans-serif}
nav{position:fixed;top:0;left:0;bottom:0;width:230px;background:#060c18;border-right:1px solid var(--line);padding:18px 0;overflow:auto}
nav .brand{padding:0 18px 16px;font-weight:700;letter-spacing:.12em;color:var(--sky);font-size:13px;border-bottom:1px solid var(--line);margin-bottom:10px}
nav .brand span{color:var(--text);font-weight:400;letter-spacing:.08em}
nav a{display:block;padding:8px 18px;color:var(--muted);text-decoration:none;border-left:3px solid transparent}
nav a:hover{color:var(--text);background:var(--panel);border-left-color:var(--blue)}
main{margin-left:230px;padding:24px 32px 60px;max-width:1400px}
header.top{background:linear-gradient(90deg,var(--navy),#0b1324 70%);border:1px solid var(--line);border-radius:8px;padding:20px 24px;margin-bottom:18px}
header.top h1{margin:0;font-size:24px;letter-spacing:.02em}
header.top .sub{color:#b9c7e2;margin-top:4px;font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.kpi{background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--blue);border-radius:6px;padding:12px 14px}
.kpi .kl{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em}
.kpi .kv2{font-size:26px;font-weight:700;margin-top:2px}.kpi .ks{color:var(--muted);font-size:12px}
.kpi.fail{border-top-color:var(--fail)}.kpi.fail .kv2{color:var(--fail)}
.kpi.warn{border-top-color:var(--warn)}.kpi.warn .kv2{color:var(--warn)}
.kpi.pass{border-top-color:var(--pass)}.kpi.pass .kv2{color:var(--pass)}
.kpi.lic{border-top-color:var(--lic)}.kpi.lic .kv2{color:var(--lic)}
.flt{position:sticky;top:0;z-index:5;background:var(--bg);padding:8px 0 12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.flt span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.1em;margin-right:4px}
.flt button{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:4px;padding:5px 12px;cursor:pointer;font:inherit;font-size:12px}
.flt button:hover{border-color:var(--blue)}.flt button.on{background:var(--blue);border-color:var(--blue);color:#fff}
.fi{margin-left:auto;color:var(--muted);font-size:12px}
.kpi.click{cursor:pointer}.kpi.click:hover{outline:1px solid var(--blue);background:var(--panel2)}
.nomatch{padding:10px 14px;background:var(--panel);border:1px dashed var(--line);border-radius:6px}
section{margin-top:26px;scroll-margin-top:60px}
section>h2{font-size:15px;letter-spacing:.14em;text-transform:uppercase;color:#fff;background:var(--navy);padding:9px 14px;border-radius:5px;margin:0 0 12px}
h3{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--sky);margin:18px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.tbl{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden;margin-bottom:6px}
.tbl th{background:var(--panel2);color:var(--muted);text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.08em;padding:8px 10px}
.tbl td{padding:7px 10px;border-top:1px solid var(--line);vertical-align:top}
.tbl tr:hover td{background:#0e1830}
.muted{color:var(--muted)}
.badge{display:inline-block;min-width:54px;text-align:center;padding:1px 8px;border-radius:3px;font-size:11px;font-weight:700;letter-spacing:.06em;border:1px solid}
.b-pass{color:var(--pass);border-color:var(--pass);background:#06210f}.b-warn{color:var(--warn);border-color:var(--warn);background:#2a1d04}
.b-fail{color:var(--fail);border-color:var(--fail);background:#2b0b0b}.b-info{color:var(--sky);border-color:var(--sky);background:#06222f}
.b-nolic{color:var(--lic);border-color:var(--lic);background:#14153a}.b-error{color:var(--muted);border-color:var(--muted);background:#111}
.st-on{color:var(--pass);border-color:var(--pass);background:#06210f}.st-off{color:var(--muted);border-color:var(--muted);background:#111}.st-reportonly{color:var(--warn);border-color:var(--warn);background:#2a1d04}
.yes{color:var(--sky);font-weight:700}.no{color:var(--fail);font-weight:700}
.barrow{display:grid;grid-template-columns:230px 1fr 64px;gap:12px;align-items:center;margin:6px 0}
.bar{height:12px;background:#0a1224;border:1px solid var(--line);border-radius:6px;overflow:hidden}
.fill{height:100%}.fill.ok{background:linear-gradient(90deg,#1d4ed8,#38bdf8)}.fill.mid{background:var(--warn)}.fill.low{background:var(--fail)}
.barrow b{text-align:right}
details.card{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--blue);border-radius:6px;margin:10px 0}
details.card>summary{cursor:pointer;padding:10px 14px;font-weight:600;list-style:none}
details.card>summary em{color:var(--muted);font-weight:400;font-size:12px;margin-left:12px}
details.card>summary::-webkit-details-marker{display:none}
details.card>summary::before{content:"\25B6";color:var(--sky);display:inline-block;vertical-align:middle;width:18px;font-size:12px;transition:transform .15s}
details.card[open]>summary::before{transform:rotate(90deg)}
details.card[open]>summary{border-bottom:1px solid var(--line)}
.kvs{padding:8px 14px 12px}
.kv{display:grid;grid-template-columns:190px 1fr;gap:10px;padding:3px 0}
.cols2{display:grid;grid-template-columns:1fr 1fr;gap:18px;align-items:start}
.cols2>div{min-width:0}
tr.grp td{background:#0a1530;color:var(--sky);font-size:11px;letter-spacing:.12em;text-transform:uppercase;padding:6px 10px;border-top:1px solid var(--line)}
tr.grp:hover td{background:#0a1530}
details.passes{margin-top:10px;background:var(--panel);border:1px solid var(--line);border-radius:6px}
details.passes>summary{cursor:pointer;color:var(--sky);padding:9px 14px}
details.passes>.tbl{margin:0;border:none;border-top:1px solid var(--line);border-radius:0}
.okmsg{padding:10px 14px;background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--pass);border-radius:6px}
.kv>span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em;padding-top:2px}
.kv>div{white-space:pre-wrap;word-break:break-word}
.kv.k-in>div{color:#7dd3fc}.kv.k-out>div{color:var(--warn)}.kv.k-bad>div{color:var(--fail)}.kv.k-grant>div{color:#fff;font-weight:600}.kv.k-sess>div{color:#a5b4fc}.kv.k-dim>div{color:var(--muted)}
ul.mem{margin:6px 0 2px;padding-left:20px;color:var(--text)}
.tbl ul.mem{max-height:380px;overflow:auto}.tbl details.mini{margin-top:4px}ul.mem li{margin:1px 0}
details.mini summary{cursor:pointer;color:var(--sky)}details.mini div{color:var(--muted);padding:4px 0}
ol.fix{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px 12px 12px 36px;margin:0}
ol.fix li{margin:4px 0}ol.fix li span{color:var(--muted)}
footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
@media(max-width:1100px){.cols2{grid-template-columns:1fr}}
@media(max-width:900px){nav{display:none}main{margin-left:0;padding:16px}.barrow{grid-template-columns:1fr}.kv{grid-template-columns:1fr}}
.hrow{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
.pdfwrap{text-align:right}
.pdfbtn{background:var(--blue);color:#fff;border:1px solid #60a5fa;border-radius:5px;padding:9px 16px;cursor:pointer;font:inherit;font-weight:600;letter-spacing:.03em}
.pdfbtn:hover{background:#2563eb}
.pdfhint{display:block;color:#b9c7e2;font-size:11px;margin-top:5px}
@page{size:A4 landscape;margin:8mm}
@media print{
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
html,body{background:#04070d!important;color:#e8eef9!important}
nav,.flt,.pdfwrap{display:none!important}
main{margin:0;padding:0;max-width:none}
.tbl ul.mem{max-height:none!important;overflow:visible!important}
tr,.kpi,.barrow,details.card,header.top{break-inside:avoid}
section>h2,h3{break-after:avoid}
details.mini summary,details.card>summary{pointer-events:none}
}
html.pdfmode nav,html.pdfmode .flt,html.pdfmode .pdfwrap{display:none!important}
html.pdfmode body{width:1280px;margin:0}
html.pdfmode main{margin:0!important;padding:24px 32px!important;max-width:none!important}
html.pdfmode .cols2{grid-template-columns:1fr 1fr!important}
html.pdfmode .barrow{grid-template-columns:230px 1fr 64px!important}
html.pdfmode .kv{grid-template-columns:190px 1fr!important}
html.pdfmode .kpis{grid-template-columns:repeat(4,1fr)!important}
html.pdfmode .tbl ul.mem{max-height:none!important;overflow:visible!important}
'@
    $js = @'
(function(){
var btns=document.querySelectorAll('.flt button'),rows=document.querySelectorAll('tr[data-status]'),info=document.getElementById('fltinfo');
var labels={all:'All',fail:'Fail',warn:'Warn',nolic:'License gaps',pass:'Pass',info:'Info'};
function count(s){var n=0;rows.forEach(function(r){if(s==='all'||r.getAttribute('data-status')===s)n++});return n}
btns.forEach(function(b){var f=b.getAttribute('data-f');b.textContent=labels[f]+' ('+count(f)+')'});
var tabs=document.querySelectorAll('table.chk');
tabs.forEach(function(t){if(!t.closest('details.passes')){var p=document.createElement('p');p.className='muted nomatch';p.style.display='none';p.textContent='No checks match this filter in this section.';t.parentNode.insertBefore(p,t.nextSibling);t._p=p}});
var cur='all';
function apply(s,scroll){
 cur=s;
 btns.forEach(function(x){x.classList.toggle('on',x.getAttribute('data-f')===s)});
 var shown=0;
 rows.forEach(function(r){var ok=(s==='all'||r.getAttribute('data-status')===s);r.style.display=ok?'':'none';if(ok)shown++});
 tabs.forEach(function(t){
  var any=false;
  t.querySelectorAll('tbody tr[data-status]').forEach(function(r){if(r.style.display!=='none')any=true});
  var grp=null,ga=false;
  t.querySelectorAll('tbody tr').forEach(function(r){
   if(r.classList.contains('grp')){if(grp)grp.style.display=ga?'':'none';grp=r;ga=false}
   else if(r.style.display!=='none'){ga=true}
  });
  if(grp)grp.style.display=ga?'':'none';
  var box=t.closest('details.passes');
  if(box){box.style.display=any?'':'none';if(any&&(s==='pass'||s==='info'))box.open=true}
  else{t.style.display=any?'':'none';if(t._p)t._p.style.display=any?'none':''}
 });
 if(info)info.textContent='Showing '+shown+' of '+rows.length+' checks'+(s==='all'?'':' - filter: '+labels[s]);
 if(scroll){var r=document.querySelector('tr[data-status]:not([style*="none"])');if(r&&s!=='all')r.scrollIntoView({behavior:'smooth',block:'center'})}
}
document.addEventListener('click',function(e){var el=e.target.closest?e.target.closest('[data-f]'):null;if(!el)return;apply(el.getAttribute('data-f'),true)});
apply('all',false);
var printing=false,wasOpen=[],prevF='all';
function beforePrint(){if(printing)return;printing=true;prevF=cur;apply('all',false);wasOpen=[];document.querySelectorAll('details').forEach(function(d){wasOpen.push(d.open);d.open=true})}
function afterPrint(){if(!printing)return;printing=false;document.querySelectorAll('details').forEach(function(d,i){d.open=wasOpen[i]});apply(prevF,false)}
window.addEventListener('beforeprint',beforePrint);window.addEventListener('afterprint',afterPrint);
var pb=document.getElementById('pdfbtn'),pd=document.getElementById('pdf64'),hint=document.getElementById('pdfhint');
function downloadPdf(){
 try{var bin=atob(pd.textContent.replace(/\s+/g,''));var n=bin.length,arr=new Uint8Array(n);for(var i=0;i<n;i++)arr[i]=bin.charCodeAt(i);
 var u=URL.createObjectURL(new Blob([arr],{type:'application/pdf'}));var l=document.createElement('a');l.href=u;l.download=pd.getAttribute('data-name')||'M365-Security-Report.pdf';
 document.body.appendChild(l);l.click();document.body.removeChild(l);setTimeout(function(){URL.revokeObjectURL(u)},4000)}catch(e){window.print()}
}
if(pb){
 if(!pd){pb.innerHTML='Print / Save as PDF';if(hint)hint.textContent='Opens the print dialog - choose Save as PDF'}
 pb.addEventListener('click',function(){if(pd){downloadPdf()}else{window.print()}});
}
if(location.hash==='#pdf'){
 document.documentElement.classList.add('pdfmode');
 apply('all',false);document.querySelectorAll('details').forEach(function(d){d.open=true});
 window.addEventListener('load',function(){setTimeout(function(){
  var ft=document.querySelector('footer'),h=Math.min(Math.ceil((ft?ft.getBoundingClientRect().bottom:document.documentElement.scrollHeight)+window.pageYOffset)+40,19000);
  var st=document.createElement('style');st.textContent='@page{size:1280px '+h+'px;margin:0}';document.head.appendChild(st);
 },300)});
}
})();
'@

    $f   = $script:Findings
    $cnt = @{}; foreach ($s in 'FAIL', 'WARN', 'NOLIC', 'PASS', 'INFO', 'ERROR') { $cnt[$s] = @($f | Where-Object Status -eq $s).Count }
    $gaRow  = @($script:RoleRows | Where-Object Role -eq 'Global Administrator') | Select-Object -First 1
    $caOn   = @($script:CARows | Where-Object State -eq 'ON').Count

    Emit '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    Emit ('<title>M365 Security Posture - {0}</title><style>{1}</style></head><body>' -f (Esc $script:Tenant.Name), $css)
    Emit '<nav><div class="brand">M365 SECURITY<br><span>POSTURE REPORT</span></div>'
    foreach ($n in @(@('overview', 'Overview'), @('licensing', '1  Licensing'), @('mfa', '2  MFA enforcement'), @('ca', '3  Conditional Access'), @('entra', '4  Entra, SharePoint & roles'), @('intune', '5  Intune'), @('exchange', '6  Exchange Online'), @('defender', '7  Defender'))) {
        Emit ('<a href="#{0}">{1}</a>' -f $n[0], $n[1])
    }
    Emit '</nav><main>'
    Emit ('<header class="top"><div class="hrow"><div><h1>{0}</h1><div class="sub">{1} &middot; Tenant ID {2} &middot; Run {3} by {4} &middot; READ-ONLY</div></div><div class="pdfwrap"><button class="pdfbtn" id="pdfbtn" type="button" title="Opens the print dialog - choose Save as PDF">&darr; Download PDF</button><span class="pdfhint" id="pdfhint">Saves a PDF straight to your Downloads folder</span></div></div></header>' -f (Esc $script:Tenant.Name), (Esc $script:Tenant.Domain), (Esc $script:Tenant.Id), (Get-Date -Format 'yyyy-MM-dd HH:mm'), (Esc $env:USERNAME))

    Emit '<div class="kpis">'
    Emit-Kpi 'Failing' "$($cnt['FAIL'])" 'click to filter' 'fail' 'fail'
    Emit-Kpi 'Warnings' "$($cnt['WARN'])" 'click to filter' 'warn' 'warn'
    Emit-Kpi 'Passing' "$($cnt['PASS'])" 'click to filter' 'pass' 'pass'
    Emit-Kpi 'Licensing gaps' "$($cnt['NOLIC'])" 'click to filter' 'lic' 'nolic'
    if ($script:MfaStats) { Emit-Kpi 'MFA registered' ("{0} / {1}" -f $script:MfaStats.Registered, $script:MfaStats.Total) 'users registered for MFA' $(if ($script:MfaStats.NotRegistered) { 'warn' } else { '' }) } else { Emit-Kpi 'MFA registered' 'n/a' 'needs Entra P1 report' }
    if ($gaRow) { Emit-Kpi 'Global admins' "$($gaRow.Count)" 'recommended 2-4' $(if ($gaRow.Status -eq 'PASS') { '' } else { 'warn' }) }
    Emit-Kpi 'CA policies ON' ("{0} / {1}" -f $caOn, @($script:CARows).Count) 'enforced / total'
    $devTxt = if ($script:IntuneData) { "$($script:IntuneData.Total)" } elseif ($Lic.Intune) { '0' } else { 'n/a' }
    Emit-Kpi 'Intune devices' $devTxt $(if ($Lic.Intune) { 'enrolled' } else { 'not licensed' })
    Emit '</div>'

    Emit '<div class="flt"><span>Filter checks</span><button class="on" data-f="all">All</button><button data-f="fail">Fail</button><button data-f="warn">Warn</button><button data-f="nolic">License gaps</button><button data-f="pass">Pass</button><button data-f="info">Info</button><span class="fi" id="fltinfo"></span></div>'

    # ---- Overview ----
    Emit '<section id="overview"><h2>Overview - fix first</h2>'
    $fails = @($f | Where-Object Status -eq 'FAIL')
    if ($fails) {
        Emit '<ol class="fix">'
        foreach ($x in $fails) { Emit ('<li><b>[{0}] {1}</b> - {2}<br><span>{3}</span></li>' -f (Esc $x.Area), (Esc $x.Check), (Esc $x.Current), (Esc $x.Guidance)) }
        Emit '</ol>'
    }
    else { Emit '<p class="muted">No failing checks.</p>' }
    Emit '</section>'

    # ---- 1 Licensing ----
    Emit '<section id="licensing"><h2>1 &middot; Tenant &amp; licensing</h2>'
    Emit ('<table class="tbl"><tbody><tr><td class="muted">Tenant</td><td>{0}</td></tr><tr><td class="muted">Primary domain</td><td>{1}</td></tr><tr><td class="muted">Tenant ID</td><td>{2}</td></tr></tbody></table>' -f (Esc $script:Tenant.Name), (Esc $script:Tenant.Domain), (Esc $script:Tenant.Id))
    Emit '<div class="cols2"><div><h3>Subscriptions</h3><table class="tbl"><thead><tr><th>SKU</th><th>Purchased</th><th>Assigned</th><th>Status</th></tr></thead><tbody>'
    foreach ($r in $skuRows) { Emit ('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (Esc $r.Sku), $r.Purchased, $r.Assigned, (Esc $r.Status)) }
    Emit '</tbody></table></div><div><h3>What this licensing unlocks</h3><table class="tbl"><thead><tr><th>Capability</th><th>License required</th><th>Tenant has it?</th></tr></thead><tbody>'
    foreach ($r in $featureRows) { Emit ('<tr><td>{0}</td><td class="muted">{1}</td><td class="{2}">{3}</td></tr>' -f (Esc $r.Capability), (Esc $r.LicenseRequired), $(if ($r.TenantHasIt) { 'yes' } else { 'no' }), $(if ($r.TenantHasIt) { 'YES' } else { 'NO' })) }
    Emit '</tbody></table></div></div><p class="muted">A SKU in the tenant does not mean every user is licensed. Conditional Access needs P1 for every user a policy covers - compare Assigned vs. your user count.</p></section>'

    # ---- 2 MFA ----
    Emit '<section id="mfa"><h2>2 &middot; MFA enforcement</h2><div class="cols2"><div>'
    if ($script:MfaStats) {
        $m = $script:MfaStats
        Emit '<h3>MFA registration coverage</h3>'
        Emit-Bar (100 * $m.Registered / [Math]::Max(1, $m.Total)) 'Users registered for MFA' ("{0} / {1}" -f $m.Registered, $m.Total)
        Emit-Bar (100 * $m.NotRegistered / [Math]::Max(1, $m.Total)) 'Users NOT registered for MFA' ("{0} / {1}" -f $m.NotRegistered, $m.Total) -Invert
        Emit-Bar (100 * $m.Passwordless / [Math]::Max(1, $m.Total)) 'Users registered with passwordless auth' ("{0} / {1}" -f $m.Passwordless, $m.Total)
        Emit ('<p class="muted">{0} of {1} admins are not registered for MFA. Click "show all" in the checks table below to see the users.</p>' -f @($m.AdminsNotRegistered).Count, $m.AdminTotal)
    }
    else { Emit '<p class="muted">MFA registration report not available (requires Entra ID P1/P2 and the AuditLog.Read.All permission).</p>' }
    Emit '</div><div>'
    if ($script:MfaMap) {
        Emit '<h3>MFA enforcement map - every layer that can force MFA</h3><table class="tbl"><thead><tr><th>Layer</th><th>State</th></tr></thead><tbody>'
        foreach ($r in $script:MfaMap) {
            $st = Esc $r.State
            if (@($r.Items).Count) {
                $li  = (@($r.Items) | ForEach-Object { '<li>' + (Esc $_) + '</li>' }) -join ''
                $st += ('<details class="mini"><summary>show all {0}</summary><ul class="mem">{1}</ul></details>' -f @($r.Items).Count, $li)
            }
            Emit ('<tr><td>{0}</td><td>{1}</td></tr>' -f (Esc $r.Layer), $st)
        }
        Emit '</tbody></table>'
    }
    Emit '</div></div>'
    Emit '<h3>Checks</h3>'
    Emit-Findings 'MFA'
    Emit '</section>'

    # ---- 3 CA ----
    Emit '<section id="ca"><h2>3 &middot; Conditional Access</h2>'
    if (@($script:CARows).Count) {
        Emit '<h3>Policy overview</h3><table class="tbl"><thead><tr><th>#</th><th>State</th><th>Policy</th><th>Users</th><th>Apps</th><th>Grant</th></tr></thead><tbody>'
        foreach ($r in $script:CARows) {
            Emit ('<tr><td>{0}</td><td><span class="badge st-{1}">{2}</span></td><td><b>{3}</b></td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f $r.N, $r.State.ToLower().Replace('-', ''), $r.State, (Esc $r.Name), (Esc $r.Users), (Esc $r.Apps), (Esc $r.Grant))
        }
        Emit '</tbody></table><h3>Policy detail</h3>'
        foreach ($c in $script:Cards) {
            $open = if ($c.State -eq 'ON') { ' open' } else { '' }
            Emit ('<details class="card"{0}><summary><span class="badge st-{1}">{2}</span> {3}<em>last changed {4}</em></summary><div class="kvs">' -f $open, $c.State.ToLower().Replace('-', ''), $c.State, (Esc $c.Name), (Esc $c.When))
            foreach ($l in $c.Lines) {
                $cls = switch ($l.Color) { 'Green' { 'k-in' } 'Yellow' { 'k-out' } 'Red' { 'k-bad' } 'Cyan' { 'k-grant' } 'Magenta' { 'k-sess' } 'DarkGray' { 'k-dim' } default { '' } }
                $txt = (@($l.Text) | ForEach-Object { '<div>' + (Esc $_) + '</div>' }) -join ''
                Emit ('<div class="kv {0}"><span>{1}</span><div>{2}</div></div>' -f $cls, (Esc $l.Label), $txt)
            }
            Emit '</div></details>'
        }
    }
    Emit '<h3>Checks</h3>'
    Emit-Findings 'CA'
    Emit '</section>'

    # ---- 4 Entra ----
    Emit '<section id="entra"><h2>4 &middot; Entra ID, SharePoint &amp; privileged roles</h2>'
    if ($script:RoleRows.Count) {
        Emit '<h3>Admin roles (active assignments)</h3><table class="tbl"><thead><tr><th>Role</th><th>Tier</th><th>Active</th><th>Assessment</th><th>Members</th></tr></thead><tbody>'
        foreach ($r in $script:RoleRows) {
            $memItems = @(@($r.Users) | ForEach-Object { '<li>' + (Esc $_) + '</li>' })
            if ($r.Other) { $memItems += ('<li class="muted">+ {0} non-user principal(s) (service principal / group)</li>' -f $r.Other) }
            $mem = if ($memItems.Count) { ('<details class="mini"><summary>show all {0}</summary><ul class="mem">{1}</ul></details>' -f $r.Count, ($memItems -join '')) } else { '<span class="muted">-</span>' }
            Emit ('<tr><td>{1}</td><td>{2}</td><td><b>{3}</b></td><td><span class="badge b-{0}">{4}</span> {5}</td><td>{6}</td></tr>' -f $r.Status.ToLower(), (Esc $r.Role), (Esc $r.Tier), $r.Count, $r.Status, (Esc $r.Note), $mem)
        }
        Emit '</tbody></table>'
    }
    Emit '<h3>Checks</h3>'
    Emit-Findings @('Entra', 'SharePoint')
    Emit '</section>'

    # ---- 5 Intune ----
    Emit '<section id="intune"><h2>5 &middot; Microsoft Intune</h2>'
    if ($script:IntuneData) {
        Emit '<h3>Enrolled devices</h3>'
        Emit-Bar $script:IntuneData.CompliantPct 'Compliant devices'
        Emit ('<p class="muted">{0}</p>' -f (Esc ((@($script:IntuneData.OS) | ForEach-Object { "$($_.Name): $($_.Count)" }) -join '   |   ')))
    }
    if (@($script:IntunePolicies).Count) { Emit ('<details class="mini" open><summary>Compliance policies ({0})</summary><div>{1}</div></details>' -f @($script:IntunePolicies).Count, (Esc (@($script:IntunePolicies) -join ', '))) }
    Emit '<h3>Checks</h3>'
    Emit-Findings 'Intune'
    Emit '</section>'

    # ---- 6 / 7 ----
    Emit '<section id="exchange"><h2>6 &middot; Exchange Online</h2>'; Emit-Findings 'Exchange'; Emit '</section>'
    Emit '<section id="defender"><h2>7 &middot; Microsoft Defender (EOP / MDO)</h2>'; Emit-Findings 'Defender'; Emit '</section>'

    Emit ('<footer>Generated by M365SecurityPosture.ps1 &middot; read-only audit - no settings were changed &middot; {0}</footer>' -f (Get-Date -Format 'yyyy-MM-dd HH:mm'))
    if ($PdfBase64) { Emit ('<script type="text/plain" id="pdf64" data-name="{0}">{1}</script>' -f (Esc $PdfName), $PdfBase64) }
    Emit ('<script>{0}</script></main></body></html>' -f $js)

    [System.IO.File]::WriteAllText($Path, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
}

function Export-ConfigSnapshot {
    # Best-effort JSON snapshot of the current policy configuration - useful as "before" documentation for rollback.
    param([string]$Path)
    $snap = [ordered]@{ GeneratedAt = (Get-Date).ToString('s'); Tenant = $script:Tenant }
    function Add-Snap {
        param([string]$Name, [scriptblock]$Get)
        try { $snap[$Name] = @(& $Get | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName) }
        catch { $snap[$Name] = 'Not available: ' + ($_.Exception.Message -split "`n")[0] }
    }
    Add-Snap 'AntiPhishPolicies'            { Get-AntiPhishPolicy }
    Add-Snap 'AntiSpamPolicies'             { Get-HostedContentFilterPolicy }
    Add-Snap 'AntiMalwarePolicies'          { Get-MalwareFilterPolicy }
    Add-Snap 'ConnectionFilter'             { Get-HostedConnectionFilterPolicy }
    Add-Snap 'OutboundSpamPolicies'         { Get-HostedOutboundSpamFilterPolicy }
    Add-Snap 'QuarantinePolicies'           { Get-QuarantinePolicy }
    Add-Snap 'SafeLinksPolicies'            { Get-SafeLinksPolicy }
    Add-Snap 'SafeAttachmentPolicies'       { Get-SafeAttachmentPolicy }
    Add-Snap 'AtpPolicyForO365'             { Get-AtpPolicyForO365 }
    Add-Snap 'EOPProtectionPolicyRules'     { Get-EOPProtectionPolicyRule }
    Add-Snap 'ATPProtectionPolicyRules'     { Get-ATPProtectionPolicyRule }
    Add-Snap 'InboundConnectors'            { Get-InboundConnector }
    Add-Snap 'OutboundConnectors'           { Get-OutboundConnector }
    Add-Snap 'TransportRules'               { Get-TransportRule -ResultSize Unlimited }
    Add-Snap 'RemoteDomains'                { Get-RemoteDomain }
    Add-Snap 'AcceptedDomains'              { Get-AcceptedDomain }
    Add-Snap 'DkimSigningConfig'            { Get-DkimSigningConfig }
    Add-Snap 'OrganizationConfig'           { Get-OrganizationConfig }
    Add-Snap 'TransportConfig'              { Get-TransportConfig }
    Add-Snap 'ExternalInOutlook'            { Get-ExternalInOutlook }
    Add-Snap 'TenantAllowBlockSpoofItems'   { Get-TenantAllowBlockListSpoofItems }
    Add-Snap 'PhishSimOverridePolicy'       { Get-PhishSimOverridePolicy }
    Add-Snap 'PhishSimOverrideRules'        { Get-ExoPhishSimOverrideRule }
    Add-Snap 'SecOpsOverrideRules'          { Get-ExoSecOpsOverrideRule }
    Add-Snap 'SecurityDefaults'             { Get-GraphAll 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy' }
    Add-Snap 'ConditionalAccessPolicies'    { Get-GraphAll 'v1.0/identity/conditionalAccess/policies' }
    Add-Snap 'NamedLocations'               { Get-GraphAll 'v1.0/identity/conditionalAccess/namedLocations' }
    Add-Snap 'AuthorizationPolicy'          { Get-GraphAll 'v1.0/policies/authorizationPolicy' }
    Add-Snap 'AuthenticationMethodsPolicy'  { Get-GraphAll 'v1.0/policies/authenticationMethodsPolicy' }
    Add-Snap 'AdminConsentRequestPolicy'    { Get-GraphAll 'v1.0/policies/adminConsentRequestPolicy' }
    Add-Snap 'SharePointSettings'           { Get-GraphAll 'v1.0/admin/sharepoint/settings' }
    $snap | ConvertTo-Json -Depth 6 -WarningAction SilentlyContinue | Set-Content -Path $Path -Encoding UTF8
}

# ----------------------------------------------------------------------------------------
#  0. Connect  (Exchange first, then Graph)
# ----------------------------------------------------------------------------------------
Write-Host ''
Write-Host '  M365 SECURITY POSTURE REPORT  (read-only)' -ForegroundColor White
Write-Host ("  Run: {0:yyyy-MM-dd HH:mm}  by {1}" -f (Get-Date), $env:USERNAME) -ForegroundColor DarkGray
Write-Host ''
Write-Host '  LEGEND  ' -NoNewline -ForegroundColor White
Write-Host '[PASS] ok  ' -NoNewline -ForegroundColor Green
Write-Host '[WARN] weak  ' -NoNewline -ForegroundColor Yellow
Write-Host '[FAIL] fix first  ' -NoNewline -ForegroundColor Red
Write-Host '[INFO] note  ' -NoNewline -ForegroundColor Cyan
Write-Host '[NOLIC] needs license  ' -NoNewline -ForegroundColor Magenta
Write-Host '[ERROR] unreadable' -ForegroundColor DarkGray

foreach ($m in 'ExchangeOnlineManagement', 'Microsoft.Graph.Authentication') {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        throw "Missing module '$m'. Install with: Install-Module $m -Scope CurrentUser"
    }
}

Write-Host '  Connecting to Exchange Online...' -ForegroundColor DarkGray
Connect-ExchangeOnline -ShowBanner:$false

Write-Host '  Connecting to Microsoft Graph (read-only scopes)...' -ForegroundColor DarkGray
Connect-MgGraph -NoWelcome -Scopes 'Policy.Read.All', 'Directory.Read.All', 'Organization.Read.All', 'RoleManagement.Read.Directory',
    'User.Read.All', 'UserAuthenticationMethod.Read.All', 'AuditLog.Read.All',
    'DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All',
    'DeviceManagementServiceConfig.Read.All', 'DeviceManagementApps.Read.All', 'SharePointTenantSettings.Read.All'

# ----------------------------------------------------------------------------------------
#  1. LICENSING  (always first)
# ----------------------------------------------------------------------------------------
Write-Host ''
Write-Host '  Connected. Collecting data - the SUMMARY and HTML REPORT LINK will be shown first, followed by the detailed results.' -ForegroundColor DarkGray
trap {
    # A fatal error mid-run must not swallow what was already collected.
    $script:Buffering = $false
    Write-Progress -Id 1 -Activity 'Collecting security data' -Completed
    Show-Buffered
    Write-Host ("  FATAL: {0}" -f $_.Exception.Message) -ForegroundColor Red
    break
}
$script:Buffering = $true
Write-Section '1' 'Tenant & licensing'

$org     = Get-GraphAll 'v1.0/organization'
$org     = @($org)[0]
$skus    = @(Get-GraphAll 'v1.0/subscribedSkus')
$primary = ($org.verifiedDomains | Where-Object isDefault).name
$script:Tenant = [pscustomobject]@{ Name = $org.displayName; Domain = $primary; Id = $org.id }

Write-Host "  Tenant : " -NoNewline; Write-Host $org.displayName -ForegroundColor White
Write-Host ("  Domain : {0}" -f $primary)
Write-Host ("  ID     : {0}" -f $org.id)

$friendly = @{
    SPE_E3 = 'Microsoft 365 E3'; SPE_E5 = 'Microsoft 365 E5'; SPE_F1 = 'Microsoft 365 F3'
    SPB = 'Microsoft 365 Business Premium'; O365_BUSINESS_PREMIUM = 'Microsoft 365 Business Standard'
    O365_BUSINESS_ESSENTIALS = 'Microsoft 365 Business Basic'; ENTERPRISEPACK = 'Office 365 E3'
    ENTERPRISEPREMIUM = 'Office 365 E5'; STANDARDPACK = 'Office 365 E1'; EMS = 'EMS E3'
    EMSPREMIUM = 'EMS E5'; AAD_PREMIUM = 'Entra ID P1'; AAD_PREMIUM_P2 = 'Entra ID P2'
    ATP_ENTERPRISE = 'Defender for Office 365 P1'; THREAT_INTELLIGENCE = 'Defender for Office 365 P2'
    EXCHANGESTANDARD = 'Exchange Online (Plan 1)'; EXCHANGEENTERPRISE = 'Exchange Online (Plan 2)'
    DESKLESSPACK = 'Office 365 F3'; WINDOWS_STORE = 'Windows Store for Business'
}

Write-SubSection 'Subscriptions (SKUs)' -Now
Write-Host ("  {0,-40} {1,9} {2,9}  {3}" -f 'SKU', 'Purchased', 'Assigned', 'Status') -ForegroundColor DarkGray
$skuRows = foreach ($s in ($skus | Sort-Object skuPartNumber)) {
    $name = if ($friendly[$s.skuPartNumber]) { $friendly[$s.skuPartNumber] } else { $s.skuPartNumber }
    $col  = if ($s.capabilityStatus -eq 'Enabled') { 'Green' } else { 'Yellow' }
    Write-Host ("  {0,-40} {1,9} {2,9}  " -f $name, $s.prepaidUnits.enabled, $s.consumedUnits) -NoNewline
    Write-Host $s.capabilityStatus -ForegroundColor $col
    [pscustomobject]@{ Sku = $name; Part = $s.skuPartNumber; Purchased = $s.prepaidUnits.enabled; Assigned = $s.consumedUnits; Status = $s.capabilityStatus }
}

# Active service plans across all enabled SKUs
$activePlans = @($skus | Where-Object capabilityStatus -eq 'Enabled' | ForEach-Object {
    $sku = $_.skuPartNumber
    $_.servicePlans | Where-Object provisioningStatus -eq 'Success' | ForEach-Object {
        [pscustomobject]@{ Plan = $_.servicePlanName; Sku = $sku }
    }
})

function Test-Licensed {
    param([string[]]$PlanPatterns)
    foreach ($p in $PlanPatterns) {
        $hit = $activePlans | Where-Object { $_.Plan -like $p } | Select-Object -First 1
        if ($hit) { return $true }
    }
    return $false
}

$Lic = [ordered]@{
    EntraFree = $true
    EntraP1   = Test-Licensed 'AAD_PREMIUM', 'AAD_PREMIUM_P2'
    EntraP2   = Test-Licensed 'AAD_PREMIUM_P2'
    EXO       = Test-Licensed 'EXCHANGE_S_*'
    MDO1      = Test-Licensed 'ATP_ENTERPRISE', 'THREAT_INTELLIGENCE'
    MDO2      = Test-Licensed 'THREAT_INTELLIGENCE'
    MDE1      = Test-Licensed 'MDE_LITE', 'MDE_SMB', 'WINDEFATP'
    MDE2      = Test-Licensed 'WINDEFATP'
    Intune    = Test-Licensed 'INTUNE_A*'
}

Write-SubSection 'What this licensing unlocks' -Now
Write-Host ("  {0,-44} {1,-30} {2}" -f 'Security capability', 'License required', 'Tenant has it?') -ForegroundColor DarkGray
$featureDefs = @(
    @{ Cap = 'Security Defaults (baseline MFA / legacy-auth block)'; Req = 'Entra ID Free (all tenants)';  Key = 'EntraFree' }
    @{ Cap = 'Conditional Access (custom policies)';                 Req = 'Entra ID P1';                  Key = 'EntraP1' }
    @{ Cap = 'Identity Protection / risk-based CA';                  Req = 'Entra ID P2';                  Key = 'EntraP2' }
    @{ Cap = 'Privileged Identity Management (JIT admin)';           Req = 'Entra ID P2';                  Key = 'EntraP2' }
    @{ Cap = 'Exchange Online Protection (anti-spam/malware)';       Req = 'Any Exchange Online plan';     Key = 'EXO' }
    @{ Cap = 'Safe Links / Safe Attachments / impersonation';        Req = 'Defender for O365 P1 or P2';   Key = 'MDO1' }
    @{ Cap = 'Threat Explorer, AIR, attack simulation';              Req = 'Defender for O365 P2';         Key = 'MDO2' }
    @{ Cap = 'Defender for Endpoint (P1 / Business)';                Req = 'MDE P1 / M365 Business Prem';  Key = 'MDE1' }
    @{ Cap = 'Defender for Endpoint P2 (EDR, hunting)';              Req = 'MDE P2';                       Key = 'MDE2' }
    @{ Cap = 'Intune device compliance (for CA grants)';             Req = 'Intune Plan 1';                Key = 'Intune' }
)
$featureRows = foreach ($f in $featureDefs) {
    $has  = [bool]$Lic[$f.Key]
    $mark = if ($has) { 'YES' } else { 'NO' }
    $col  = if ($has) { 'Green' } else { 'Red' }
    Write-Host ("  {0,-44} {1,-30} " -f $f.Cap, $f.Req) -NoNewline
    Write-Host $mark -ForegroundColor $col
    [pscustomobject]@{ Capability = $f.Cap; LicenseRequired = $f.Req; TenantHasIt = $has }
}
Write-Host ''
Write-Host '  NOTE: A SKU in the tenant does not mean every user is licensed. Conditional Access' -ForegroundColor DarkGray
Write-Host '        needs P1 for EVERY user the policy covers. Compare Assigned vs. your user count.' -ForegroundColor DarkGray


# ----------------------------------------------------------------------------------------
#  Pre-fetch Conditional Access data (used by sections 2, 3 and 5)
# ----------------------------------------------------------------------------------------
$CAPolicies = @(); $CAError = $null
if ($Lic.EntraP1) {
    try { $CAPolicies = @(Get-GraphAll 'v1.0/identity/conditionalAccess/policies') }
    catch { $CAError = ($_.Exception.Message -split "`n")[0] }
}
$CAOn  = @($CAPolicies | Where-Object state -eq 'enabled')
$CAMfa = @($CAOn | Where-Object { Test-RequiresMfa $_ })

# ----------------------------------------------------------------------------------------
#  2. MFA ENFORCEMENT (beyond / alongside Conditional Access)
# ----------------------------------------------------------------------------------------
Write-Section '2' 'MFA enforcement - Security Defaults, per-user MFA, registration'

$script:sdOn = $null
$script:perUserEnforced = $null
$script:perUserEnabled  = $null

Write-SubSection 'Security Defaults'
Invoke-Safe 'MFA' 'Security Defaults' {
    $sd = Get-GraphAll 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    $script:sdOn = [bool]$sd.isEnabled
    if ($sd.isEnabled) {
        Add-Finding 'MFA' 'Security Defaults' PASS 'ON - tenant-wide baseline MFA is enforced (free)'
        Write-Host '          Enforces: MFA registration for all users, MFA for admins, MFA for users when risk is' -ForegroundColor DarkGray
        Write-Host '                    detected, blocks legacy authentication, MFA for privileged Azure actions.' -ForegroundColor DarkGray
    }
    elseif ($Lic.EntraP1) {
        Add-Finding 'MFA' 'Security Defaults' INFO 'OFF - acceptable only if Conditional Access covers the same controls (Section 3)'
    }
    else {
        Add-Finding 'MFA' 'Security Defaults' FAIL 'OFF and tenant has no Entra P1 for Conditional Access' `
            'Enable Security Defaults - it is the only baseline MFA available on Entra Free.' 'Free'
    }
}

Write-SubSection 'Per-user MFA (legacy setting)'
if ($SkipPerUserMfa) {
    Add-Finding 'MFA' 'Per-user MFA' INFO 'Skipped (-SkipPerUserMfa)'
}
else {
    Invoke-Safe 'MFA' 'Per-user MFA' {
        $all   = @(Get-GraphAll 'v1.0/users?$select=id,userPrincipalName,displayName,accountEnabled,userType&$top=999')
        $total = $all.Count
        $scan  = @($all | Select-Object -First $MaxUsers)
        $results = [System.Collections.Generic.List[object]]::new()
        $failed  = 0
        for ($i = 0; $i -lt $scan.Count; $i += 20) {
            Write-Progress -Id 2 -ParentId 1 -Activity 'Reading per-user MFA state' -Status ("{0} / {1} users" -f $i, $scan.Count) -PercentComplete (100 * $i / [Math]::Max(1, $scan.Count))
            $chunk = @($scan[$i..([Math]::Min($i + 19, $scan.Count - 1))])
            $reqs = @(); $n = 0
            foreach ($u in $chunk) { $n++; $reqs += @{ id = "$n"; method = 'GET'; url = "/users/$($u.id)/authentication/requirements" } }
            $body = @{ requests = $reqs } | ConvertTo-Json -Depth 4
            $r = Invoke-MgGraphRequest -Method POST -Uri 'beta/$batch' -Body $body -ContentType 'application/json' -OutputType PSObject
            foreach ($resp in $r.responses) {
                $u = $chunk[[int]$resp.id - 1]
                if ($resp.status -eq 200) { $results.Add([pscustomobject]@{ Upn = $u.userPrincipalName; State = $resp.body.perUserMfaState; Enabled = $u.accountEnabled }) }
                else { $failed++ }
            }
        }
        Write-Progress -Id 2 -Activity 'Reading per-user MFA state' -Completed

        $enf = @($results | Where-Object State -eq 'enforced')
        $ena = @($results | Where-Object State -eq 'enabled')
        $script:perUserEnforced = $enf.Count
        $script:PerUser = [pscustomobject]@{ Scanned = $results.Count; Total = $total; Enforced = $enf.Count; Enabled = $ena.Count; Users = @((@($enf) + @($ena)) | ForEach-Object { "$($_.Upn)  ($($_.State))" }) }
        $script:perUserEnabled  = $ena.Count

        Add-Finding 'MFA' 'Users scanned' INFO ("{0} of {1} user objects{2}" -f $results.Count, $total, $(if ($failed) { " ($failed unreadable)" } elseif ($total -gt $MaxUsers) { " (capped by -MaxUsers $MaxUsers)" } else { '' }))
        Add-Finding 'MFA' 'Per-user MFA: ENFORCED' $(if ($enf.Count) { 'WARN' } else { 'PASS' }) ("{0} user(s)" -f $enf.Count) `
            'Per-user MFA works outside Conditional Access and is hard to audit. Move these users to CA, then set per-user state to Disabled.'
        Set-LastFindingItems @($enf | ForEach-Object { if ($_.Enabled -eq $false) { "$($_.Upn)  (account disabled)" } else { "$($_.Upn)" } }) 15
        Add-Finding 'MFA' 'Per-user MFA: ENABLED (not yet registered)' $(if ($ena.Count) { 'WARN' } else { 'PASS' }) ("{0} user(s)" -f $ena.Count)
        Set-LastFindingItems @($ena | ForEach-Object { if ($_.Enabled -eq $false) { "$($_.Upn)  (account disabled)" } else { "$($_.Upn)" } }) 15
        Add-Finding 'MFA' 'Per-user MFA: disabled (recommended)' INFO ("{0} user(s)" -f @($results | Where-Object State -eq 'disabled').Count)
    }
}

Write-SubSection 'MFA registration coverage' -Now
if (-not $Lic.EntraP1) {
    Add-Finding 'MFA' 'MFA registration report' NOLIC 'Registration reports need Entra ID P1/P2' '' 'Entra ID P1'
}
else {
    Invoke-Safe 'MFA' 'MFA registration' {
        $reg   = @(Get-GraphAll 'v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999')
        $total = $reg.Count
        $tot   = [Math]::Max(1, $total)
        $mfaR  = @($reg | Where-Object isMfaRegistered).Count
        $notR  = $total - $mfaR
        $pwl   = @($reg | Where-Object isPasswordlessCapable).Count
        $adm   = @($reg | Where-Object isAdmin)
        $admNo = @($adm | Where-Object { -not $_.isMfaRegistered })
        $notRegUsers = @($reg | Where-Object { -not $_.isMfaRegistered } | ForEach-Object { $_.userPrincipalName })
        $pwlUsers    = @($reg | Where-Object isPasswordlessCapable | ForEach-Object { $_.userPrincipalName })
        $script:MfaStats = [pscustomobject]@{ Total = $total; Registered = $mfaR; NotRegistered = $notR; Passwordless = $pwl; AdminTotal = $adm.Count
            AdminsNotRegistered = @($admNo | ForEach-Object { $_.userPrincipalName }) }
        Write-Bar (100 * $mfaR / $tot) 'Users registered for MFA'                 -Detail ("{0} / {1}" -f $mfaR, $total)
        Write-Bar (100 * $notR / $tot) 'Users NOT registered for MFA'             -Detail ("{0} / {1}" -f $notR, $total) -Invert
        Write-Bar (100 * $pwl / $tot)  'Users registered with passwordless auth'  -Detail ("{0} / {1}" -f $pwl, $total)
        Write-Host ''
        $ratio = $mfaR / $tot
        Add-Finding 'MFA' 'Users registered for MFA' $(if ($ratio -ge 0.95) { 'PASS' } elseif ($ratio -ge 0.7) { 'WARN' } else { 'FAIL' }) ("{0} of {1} users" -f $mfaR, $total) 'Aim for every enabled user to be registered.'
        Add-Finding 'MFA' 'Users NOT registered for MFA' $(if ($notR -gt 0) { 'WARN' } else { 'PASS' }) ("{0} of {1} users" -f $notR, $total) 'Have these users register an MFA method (aka.ms/mysecurityinfo).'
        Set-LastFindingItems $notRegUsers 10
        Add-Finding 'MFA' 'Users registered with passwordless auth' INFO ("{0} of {1} users" -f $pwl, $total)
        Set-LastFindingItems $pwlUsers 0
        Add-Finding 'MFA' 'Admins registered for MFA' $(if ($admNo.Count) { 'FAIL' } else { 'PASS' }) ("{0} of {1} admins NOT registered" -f $admNo.Count, $adm.Count) `
            'Every admin must have MFA registered before enforcing policies.'
        Set-LastFindingItems @($admNo | ForEach-Object { $_.userPrincipalName }) 25
    }
}

Write-SubSection 'Legacy MFA / SSPR policy migration'
Invoke-Safe 'MFA' 'Policy migration' {
    $am = Get-GraphAll 'v1.0/policies/authenticationMethodsPolicy'
    $ms = $am.policyMigrationState
    $st = if ($ms -eq 'migrationComplete') { 'PASS' } elseif ($ms) { 'WARN' } else { 'INFO' }
    Add-Finding 'MFA' 'Authentication methods policy migration' $st $(if ($ms) { $ms } else { 'Not reported' }) `
        'Finish migrating legacy MFA and SSPR settings to the Authentication methods policy.'
}

Write-SubSection 'MFA enforcement map  (every layer that can force MFA)' -Now
$sdTxt  = if ($null -eq $script:sdOn) { 'unknown' } elseif ($script:sdOn) { 'ON' } else { 'OFF' }
$sdCol  = if ($script:sdOn) { 'Green' } else { 'DarkGray' }
$puTxt  = if ($null -eq $script:perUserEnforced) { 'not scanned' } else { "{0} enforced / {1} enabled" -f $script:perUserEnforced, $script:perUserEnabled }
$puCol  = if ($null -eq $script:perUserEnforced) { 'DarkGray' } elseif (($script:perUserEnforced + $script:perUserEnabled) -gt 0) { 'Yellow' } else { 'DarkGray' }
$caTxt  = if (-not $Lic.EntraP1) { 'NOT LICENSED (needs Entra P1)' } elseif ($CAError) { 'could not read' } else { "{0} enforced MFA/auth-strength policy(ies)" -f $CAMfa.Count }
$caCol  = if (-not $Lic.EntraP1) { 'Magenta' } elseif ($CAMfa.Count) { 'Green' } else { 'Red' }
$ipTxt  = if ($Lic.EntraP2) { 'Licensed - look for sign-in / user risk policies in Section 3' } else { 'NOT LICENSED (needs Entra P2)' }
$ipCol  = if ($Lic.EntraP2) { 'Cyan' } else { 'Magenta' }
Write-Host ("    {0,-46} " -f 'Security Defaults') -NoNewline;                                Write-Host $sdTxt -ForegroundColor $sdCol
Write-Host ("    {0,-46} " -f 'Per-user MFA (legacy)') -NoNewline;                            Write-Host $puTxt -ForegroundColor $puCol
Write-Host ("    {0,-46} " -f 'Conditional Access MFA policies') -NoNewline;                  Write-Host $caTxt -ForegroundColor $caCol
Write-Host ("    {0,-46} " -f 'Identity Protection risk-based MFA') -NoNewline;               Write-Host $ipTxt -ForegroundColor $ipCol
Write-Host ("    {0,-46} " -f 'Legacy MFA service settings (trusted IPs)') -NoNewline;        Write-Host 'MANUAL CHECK - not exposed via Graph (Entra > Users > Per-user MFA > service settings)' -ForegroundColor DarkGray
Write-Host ''
$caItems = @($CAMfa | ForEach-Object { "{0}   [{1}]" -f $_.displayName, (Get-CAUsersShort $_.conditions.users) })
$puItems = if ($script:PerUser) { @($script:PerUser.Users) } else { @() }
$script:MfaMap = @(
    [pscustomobject]@{ Layer = 'Security Defaults';                         State = $sdTxt; Items = @() }
    [pscustomobject]@{ Layer = 'Per-user MFA (legacy)';                     State = $puTxt; Items = $puItems }
    [pscustomobject]@{ Layer = 'Conditional Access MFA policies';           State = $caTxt; Items = $caItems }
    [pscustomobject]@{ Layer = 'Identity Protection risk-based MFA';        State = $ipTxt; Items = @() }
    [pscustomobject]@{ Layer = 'Legacy MFA service settings (trusted IPs)'; State = 'MANUAL CHECK - not exposed via Graph'; Items = @() }
)
foreach ($ci in $caItems) { Write-Host ("      CA policy: {0}" -f $ci) -ForegroundColor DarkGray }
if ($caItems) { Write-Host '' }
$sources = @()
if ($script:sdOn) { $sources += 'Security Defaults' }
if ($script:perUserEnforced -gt 0) { $sources += "Per-user MFA ($($script:perUserEnforced) users)" }
if ($CAMfa.Count) { $sources += "Conditional Access ($($CAMfa.Count) policy(ies))" }
if ($sources) { Add-Finding 'MFA' 'Effective MFA enforcement' PASS ($sources -join '  +  ') }
else { Add-Finding 'MFA' 'Effective MFA enforcement' FAIL 'NO MFA enforcement mechanism detected' 'Enable Security Defaults (free) or create Conditional Access MFA policies.' }
if ($script:sdOn -and $CAOn.Count -gt 0) {
    Add-Finding 'MFA' 'Security Defaults + Conditional Access overlap' WARN 'Both are active - users must satisfy both' `
        'Confirm this is intentional; most tenants turn Security Defaults off once CA covers the same controls.'
}

# ----------------------------------------------------------------------------------------
#  3. CONDITIONAL ACCESS - full policy detail
# ----------------------------------------------------------------------------------------
Write-Section '3' 'Conditional Access - every policy in detail'

if (-not $Lic.EntraP1) {
    Add-Finding 'CA' 'Conditional Access' NOLIC 'Not available - no Entra ID P1/P2 (or M365 Business Premium / E3 / E5)' `
        'Buy Entra ID P1 (included in M365 Business Premium, E3, E5) or rely on Security Defaults.' 'Entra ID P1'
}
elseif ($CAError) {
    Add-Finding 'CA' 'Conditional Access' ERROR "Licensed but could not read policies: $CAError"
}
elseif ($CAPolicies.Count -eq 0) {
    Add-Finding 'CA' 'Conditional Access policies' FAIL 'Licensed for Conditional Access but ZERO policies exist' `
        'Create baseline policies: block legacy auth, MFA for admins, MFA for all users.' 'Entra ID P1'
}
else {
    Invoke-Safe 'CA' 'Conditional Access' {
        # ---- resolve names once ----
        foreach ($t in (Get-GraphAll 'v1.0/directoryRoleTemplates')) { $script:RoleMap[$t.id] = $t.displayName }
        try {
            foreach ($l in (Get-GraphAll 'v1.0/identity/conditionalAccess/namedLocations')) {
                if ($l.'@odata.type' -like '*ipNamedLocation') {
                    $rng = @($l.ipRanges | ForEach-Object { $_.cidrAddress })
                    $shown = ($rng | Select-Object -First 6) -join ', '
                    if ($rng.Count -gt 6) { $shown += " (+$($rng.Count - 6) more)" }
                    $script:LocMap[$l.id] = "{0}  [IP ranges{1}]  {2}" -f $l.displayName, $(if ($l.isTrusted) { ', TRUSTED' } else { '' }), $shown
                }
                else {
                    $script:LocMap[$l.id] = "{0}  [Countries: {1}]" -f $l.displayName, (@($l.countriesAndRegions) -join ', ')
                }
            }
        } catch { }
        $ids = foreach ($p in $CAPolicies) {
            $u = $p.conditions.users
            $u.includeUsers; $u.excludeUsers; $u.includeGroups; $u.excludeGroups
        }
        Resolve-Ids (Get-Arr $ids)

        # ---- overview table ----
        $enf = @($CAPolicies | Where-Object state -eq 'enabled').Count
        $rep = @($CAPolicies | Where-Object state -eq 'enabledForReportingButNotEnforced').Count
        $off = @($CAPolicies | Where-Object state -eq 'disabled').Count
        Write-Host ''
        Write-Host '    Policies: ' -NoNewline
        Write-Host ("{0} total" -f $CAPolicies.Count) -ForegroundColor White -NoNewline; Write-Host '   ' -NoNewline
        Write-Host ("{0} ON" -f $enf) -ForegroundColor Green -NoNewline; Write-Host '   ' -NoNewline
        Write-Host ("{0} REPORT-ONLY" -f $rep) -ForegroundColor Yellow -NoNewline; Write-Host '   ' -NoNewline
        Write-Host ("{0} OFF" -f $off) -ForegroundColor DarkGray
        Write-Host ''
        Write-Host ("    {0,-3} {1,-12} {2,-36} {3,-26} {4,-16} {5}" -f '#', 'STATE', 'POLICY', 'USERS', 'APPS', 'GRANT') -ForegroundColor DarkYellow
        $i = 0
        foreach ($p in ($CAPolicies | Sort-Object @{ Expression = { switch ($_.state) { 'enabled' { 0 } 'enabledForReportingButNotEnforced' { 1 } default { 2 } } } }, displayName)) {
            $i++
            $stateTxt = switch ($p.state) { 'enabled' { 'ON' } 'disabled' { 'OFF' } default { 'REPORT-ONLY' } }
            $stateCol = switch ($p.state) { 'enabled' { 'Green' } 'disabled' { 'DarkGray' } default { 'Yellow' } }
            $apps = if ($p.conditions.applications.includeApplications -contains 'All') { 'All apps' }
                    elseif (Get-Arr $p.conditions.applications.includeUserActions) { 'User action' }
                    else { "$(@(Get-Arr $p.conditions.applications.includeApplications).Count) app(s)" }
            $grant = Get-CAGrantShort $p
            Write-Host ("    {0,-3} " -f $i) -NoNewline
            Write-Host ("{0,-12} " -f $stateTxt) -ForegroundColor $stateCol -NoNewline
            Write-Host ("{0,-36} " -f (Cut $p.displayName 36)) -ForegroundColor White -NoNewline
            Write-Host ("{0,-26} {1,-16} " -f (Cut (Get-CAUsersShort $p.conditions.users) 26), $apps) -NoNewline
            Write-Host $grant -ForegroundColor $(if ($grant -like '*BLOCK*') { 'Red' } else { 'Cyan' })
            $script:CARows.Add([pscustomobject]@{ N = $i; State = $stateTxt; Name = $p.displayName; Users = (Get-CAUsersShort $p.conditions.users); Apps = $apps; Grant = $grant })
        }

        # ---- detailed cards ----
        if ($script:Detailed) { Write-SubSection 'Policy detail cards' -Now } else { $script:Quiet = $true }
        foreach ($p in ($CAPolicies | Sort-Object @{ Expression = { switch ($_.state) { 'enabled' { 0 } 'enabledForReportingButNotEnforced' { 1 } default { 2 } } } }, displayName)) {
            Show-CAPolicy $p
        }
        $script:Quiet = $false
        if (-not $script:Detailed) { Write-Host '  Per-policy details (users, exclusions, locations, grant and session controls) are in the HTML report; use -Detailed to print them here.' -ForegroundColor DarkGray }
    }

    Write-SubSection 'Coverage checks (based on ENFORCED policies)'
    Invoke-Safe 'CA' 'Coverage checks' {
        $reportOn = @($CAPolicies | Where-Object state -eq 'enabledForReportingButNotEnforced')
        $legacy = @($CAOn | Where-Object {
            $_.conditions.users.includeUsers -contains 'All' -and $_.grantControls.builtInControls -contains 'block' -and
            ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or $_.conditions.clientAppTypes -contains 'other') })
        $mfaAll = @($CAMfa | Where-Object { $_.conditions.users.includeUsers -contains 'All' -and $_.conditions.applications.includeApplications -contains 'All' })
        $mfaAdmin = @($CAMfa | Where-Object { @($_.conditions.users.includeRoles).Count -gt 0 })
        $riskSign = @($CAOn | Where-Object { Get-Arr $_.conditions.signInRiskLevels })
        $riskUser = @($CAOn | Where-Object { Get-Arr $_.conditions.userRiskLevels })
        $regInfo  = @($CAOn | Where-Object { $_.conditions.applications.includeUserActions -contains 'urn:user:registersecurityinfo' })

        Add-Finding 'CA' 'Block legacy authentication' $(if ($legacy) { 'PASS' } else { 'FAIL' }) `
            $(if ($legacy) { "Enforced by: $($legacy[0].displayName)" } else { 'No enforced policy found' }) `
            'Create a CA policy: All users, client apps = Exchange ActiveSync + Other, Block.' 'Entra ID P1'
        Add-Finding 'CA' 'MFA for all users / all apps' $(if ($mfaAll) { 'PASS' } else { 'FAIL' }) `
            $(if ($mfaAll) { "Enforced by: $($mfaAll[0].displayName)" } else { 'No enforced all-users MFA policy' }) `
            'Require MFA (or an authentication strength) for All users on All cloud apps.' 'Entra ID P1'
        Add-Finding 'CA' 'MFA for admin roles' $(if ($mfaAdmin -or $mfaAll) { 'PASS' } else { 'FAIL' }) `
            $(if ($mfaAdmin) { "Enforced by: $($mfaAdmin[0].displayName)" } elseif ($mfaAll) { 'Covered by all-users MFA policy' } else { 'No policy targeting directory roles' }) `
            'Require phishing-resistant MFA for all directory roles.' 'Entra ID P1'
        $regRestricted = @($regInfo | Where-Object { $_.conditions.locations -or $_.grantControls.builtInControls -contains 'compliantDevice' -or $_.grantControls.builtInControls -contains 'domainJoinedDevice' -or $_.grantControls.builtInControls -contains 'block' })
        Add-Finding 'CA' 'Secure registration of security info' $(if ($regRestricted) { 'PASS' } else { 'WARN' }) `
            $(if ($regRestricted) { "Enforced by: $($regRestricted[0].displayName) (limited by location / device)" } elseif ($regInfo) { "Enforced by: $($regInfo[0].displayName), but not limited to trusted locations or compliant devices" } else { 'No policy on the "register security info" user action' }) `
            'Only allow MFA registration from trusted locations or compliant devices, so a stolen password cannot be used to register an attacker device.' 'Entra ID P1'
        if ($Lic.EntraP2) {
            Add-Finding 'CA' 'Sign-in risk policy' $(if ($riskSign) { 'PASS' } else { 'WARN' }) $(if ($riskSign) { "Enforced by: $($riskSign[0].displayName)" } else { 'None' }) 'Require MFA on medium+ sign-in risk.' 'Entra ID P2'
            Add-Finding 'CA' 'User risk policy' $(if ($riskUser) { 'PASS' } else { 'WARN' }) $(if ($riskUser) { "Enforced by: $($riskUser[0].displayName)" } else { 'None' }) 'Require password change on high user risk.' 'Entra ID P2'
        }
        else {
            Add-Finding 'CA' 'Sign-in / user risk policies' NOLIC 'Not available - requires Entra ID P2' '' 'Entra ID P2'
        }
        if ($reportOn.Count) {
            Add-Finding 'CA' 'Policies stuck in report-only' WARN ("{0}: {1}" -f $reportOn.Count, (($reportOn | ForEach-Object displayName) -join '; ')) 'Review sign-in impact, then switch to On.' 'Entra ID P1'
            Set-LastFindingItems @($reportOn | ForEach-Object { $_.displayName }) 0
        }
    }
    Invoke-Safe 'CA' 'Locations and sessions' {
        $nl = @(Get-GraphAll 'v1.0/identity/conditionalAccess/namedLocations')

        # trusted IP locations + overly broad ranges
        $trusted = @($nl | Where-Object { $_.'@odata.type' -like '*ipNamedLocation' -and $_.isTrusted -eq $true })
        $tItems = @(); $broadCount = 0
        foreach ($l in $trusted) {
            foreach ($r in @($l.ipRanges)) {
                $cidr = "$($r.cidrAddress)"; $flag = ''
                if ($cidr -match '/(\d+)$') {
                    $len = [int]$Matches[1]; $v6 = ($cidr -like '*:*')
                    if ((-not $v6 -and $len -lt 16) -or ($v6 -and $len -lt 48)) { $flag = '   <-- very broad range'; $broadCount++ }
                }
                $tItems += ("{0}: {1}{2}" -f $l.displayName, $cidr, $flag)
            }
        }
        Add-Finding 'CA' 'Trusted named locations' $(if ($broadCount) { 'WARN' } elseif ($trusted.Count) { 'PASS' } else { 'INFO' }) `
            $(if ($trusted.Count) { "{0} trusted IP location(s), {1} overly broad range(s)" -f $trusted.Count, $broadCount } else { 'None defined (recommended: add your office / WAN public IPs as trusted locations)' }) `
            'Trusted ranges should be your own public IPs only. Remove very large ranges (for example wider than /16).' 'Entra ID P1'
        Set-LastFindingItems $tItems

        # country-based policy
        $countryIds = @($nl | Where-Object { $_.'@odata.type' -like '*countryNamedLocation' } | ForEach-Object { $_.id })
        $geo = @($CAOn | Where-Object {
            $loc = $_.conditions.locations
            $loc -and @((Get-Arr $loc.includeLocations) + (Get-Arr $loc.excludeLocations) | Where-Object { $countryIds -contains $_ }).Count })
        Add-Finding 'CA' 'Country-based access policy' $(if ($geo.Count) { 'PASS' } else { 'INFO' }) `
            $(if ($geo.Count) { "{0} enforced polic(ies) use country locations" -f $geo.Count } else { 'None (optional hardening: block sign-ins from countries you do not operate in)' }) '' 'Entra ID P1'
        Set-LastFindingItems @($geo | ForEach-Object { $_.displayName })

        # sign-in frequency on MFA policies
        $sf = @($CAMfa | Where-Object { $_.sessionControls.signInFrequency.isEnabled })
        $sfItems = @($sf | ForEach-Object {
            $f = $_.sessionControls.signInFrequency
            "{0}: {1}" -f $_.displayName, $(if ($f.frequencyInterval -eq 'everyTime') { 'every time' } else { "every $($f.value) $($f.type)" }) })
        Add-Finding 'CA' 'Sign-in frequency on MFA policies' INFO ("{0} of {1} MFA policy(ies) set a sign-in frequency" -f $sf.Count, $CAMfa.Count)
        Set-LastFindingItems $sfItems 0
    }
}

# ----------------------------------------------------------------------------------------
#  4. ENTRA ID - tenant settings (identity protection, defaults, roles)
# ----------------------------------------------------------------------------------------
Write-Section '4' 'Entra ID & SharePoint - tenant settings, defaults & privileged roles'

Write-SubSection 'Identity Protection / PIM'
if (-not $Lic.EntraP2) {
    Add-Finding 'Entra' 'Risk-based CA & PIM' NOLIC 'Not available - requires Entra ID P2' `
        'Consider P2 (or Entra ID Governance) for risk-based sign-in/user policies and just-in-time admin.' 'Entra ID P2'
}
else {
    Add-Finding 'Entra' 'Risk-based CA & PIM' INFO 'Licensed - verify risk policies exist in CA list above and admin roles are PIM-eligible'
}

Write-SubSection 'Default user & guest permissions (authorization policy)'
Invoke-Safe 'Entra' 'Authorization policy' {
    $ap = Get-GraphAll 'v1.0/policies/authorizationPolicy'
    $ap = @($ap)[0]
    $perm = $ap.defaultUserRolePermissions

    Add-Finding 'Entra' 'Users can register applications' $(if ($perm.allowedToCreateApps) { 'WARN' } else { 'PASS' }) `
        (Format-Bool $perm.allowedToCreateApps) 'Set to No; use an Application Developer role instead.' 'Free'
    Add-Finding 'Entra' 'Users can create new tenants' $(if ($perm.allowedToCreateTenants) { 'WARN' } else { 'PASS' }) `
        (Format-Bool $perm.allowedToCreateTenants) 'Set to No.' 'Free'
    Add-Finding 'Entra' 'Users can create security groups' INFO (Format-Bool $perm.allowedToCreateSecurityGroups)

    $grants = @($perm.permissionGrantPoliciesAssigned)
    if ($grants.Count -eq 0) {
        Add-Finding 'Entra' 'User consent to apps' PASS 'Users cannot consent (admin consent only)'
    }
    elseif ($grants -match 'legacy') {
        Add-Finding 'Entra' 'User consent to apps' FAIL 'Legacy policy - users can consent to ANY app/permission' `
            'Use "Let Microsoft manage" or verified-publisher / low-risk permissions only.' 'Free'
    }
    else {
        Add-Finding 'Entra' 'User consent to apps' PASS ($grants -join ', ' -replace 'ManagePermissionGrantsForSelf\.', '')
    }

    $guestRole = switch ($ap.guestUserRoleId) {
        'a0b1b346-4d3e-4e8b-98f8-753987be4970' { 'Same as members (most inclusive)'; $gs = 'FAIL' }
        '10dae51f-b6af-4016-8d66-8c2a99b929b3' { 'Limited (default)';                 $gs = 'WARN' }
        '2af84b1e-32c8-42b7-82bc-daa82404023b' { 'Restricted (most secure)';          $gs = 'PASS' }
        default { $ap.guestUserRoleId; $gs = 'INFO' }
    }
    Add-Finding 'Entra' 'Guest user access level' $gs $guestRole 'Set to "restricted to own directory objects".' 'Free'

    $inv = $ap.allowInvitesFrom
    $invStatus = switch ($inv) { 'everyone' { 'FAIL' } 'adminsGuestInvitersAndAllMembers' { 'WARN' } default { 'PASS' } }
    Add-Finding 'Entra' 'Who can invite guests' $invStatus $inv 'Limit to admins and the Guest Inviter role.' 'Free'

    Add-Finding 'Entra' 'Email-verified self-join to tenant' $(if ($ap.allowEmailVerifiedUsersToJoinOrganization) { 'WARN' } else { 'PASS' }) `
        (Format-Bool $ap.allowEmailVerifiedUsersToJoinOrganization) 'Disable.' 'Free'
    Add-Finding 'Entra' 'Legacy MSOnline PowerShell blocked' $(if ($ap.blockMsolPowerShell) { 'PASS' } else { 'WARN' }) `
        (Format-Bool $ap.blockMsolPowerShell) 'Block it; attackers still use it for enumeration.' 'Free'
}

Invoke-Safe 'Entra' 'Admin consent workflow' {
    $acr = Get-GraphAll 'v1.0/policies/adminConsentRequestPolicy'
    Add-Finding 'Entra' 'Admin consent request workflow' $(if ($acr.isEnabled) { 'PASS' } else { 'WARN' }) `
        (Format-Bool $acr.isEnabled) 'Enable so blocked users can request app approval.' 'Free'
}

Write-SubSection 'Authentication methods'
Invoke-Safe 'Entra' 'Authentication methods' {
    $am = Get-GraphAll 'v1.0/policies/authenticationMethodsPolicy'
    foreach ($c in ($am.authenticationMethodConfigurations | Sort-Object id)) {
        $weak = $c.id -in 'Sms', 'Voice', 'Email'
        $st   = if ($c.state -eq 'enabled' -and $weak) { 'WARN' } elseif ($c.state -eq 'enabled') { 'PASS' } else { 'INFO' }
        $g    = if ($st -eq 'WARN') { 'Weaker factor - phase out in favour of Authenticator / FIDO2 / passkeys.' } else { '' }
        Add-Finding 'Entra' "Method: $($c.id)" $st $c.state $g
    }
}

Write-SubSection 'Privileged roles (active assignments)' -Now
$script:RoleRows = [System.Collections.Generic.List[object]]::new()
$roleDefs = @(
    @{ Id = '62e90394-69f5-4237-9190-012177145e10'; Name = 'Global Administrator';                   Tier = 'Critical' }
    @{ Id = 'e8611ab8-c189-46e8-94e1-60213ab1f814'; Name = 'Privileged Role Administrator';          Tier = 'Critical' }
    @{ Id = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'; Name = 'Privileged Authentication Administrator'; Tier = 'Critical' }
    @{ Id = '194ae4cb-b126-40b2-bd5b-6091b380977d'; Name = 'Security Administrator';                 Tier = 'High' }
    @{ Id = '29232cdf-9323-42fd-ade2-1d097af3e4de'; Name = 'Exchange Administrator';                 Tier = 'High' }
    @{ Id = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'; Name = 'SharePoint Administrator';               Tier = 'High' }
    @{ Id = 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'; Name = 'Conditional Access Administrator';       Tier = 'High' }
    @{ Id = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'; Name = 'Application Administrator';              Tier = 'High' }
    @{ Id = '158c047a-c907-4556-b7ef-446551a6b5f7'; Name = 'Cloud Application Administrator';        Tier = 'High' }
    @{ Id = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; Name = 'User Administrator';                     Tier = 'High' }
    @{ Id = '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'; Name = 'Hybrid Identity Administrator';          Tier = 'High' }
    @{ Id = 'c4e39bd9-1100-46d3-8c65-fb160da0071f'; Name = 'Authentication Administrator';           Tier = 'Medium' }
    @{ Id = '3a2c62db-5318-420d-8d74-23affee5d9d5'; Name = 'Intune Administrator';                   Tier = 'Medium' }
    @{ Id = '729827e3-9c14-49f7-bb1b-9608f156bbb8'; Name = 'Helpdesk Administrator';                 Tier = 'Medium' }
)
Write-Host ("    {0,-42} {1,-9} {2,7}   {3}" -f 'ROLE', 'TIER', 'ACTIVE', 'ASSESSMENT') -ForegroundColor DarkYellow
$allPriv = @{}
foreach ($rd in $roleDefs) {
    $members = @(); $note = ''
    try {
        $role    = Get-GraphAll ("v1.0/directoryRoles(roleTemplateId='{0}')" -f $rd.Id)
        $members = @(Get-GraphAll ("v1.0/directoryRoles/{0}/members" -f $role.id))
    }
    catch { $note = 'role not activated' }
    $upns  = @($members | Where-Object { $_.userPrincipalName } | ForEach-Object { $_.userPrincipalName })
    $other = $members.Count - $upns.Count
    foreach ($u in $upns) { $allPriv[$u] = $true }

    if ($rd.Name -eq 'Global Administrator') {
        $st   = if ($members.Count -lt 2) { 'WARN' } elseif ($members.Count -ge 5) { 'FAIL' } else { 'PASS' }
        $text = if ($members.Count -lt 2) { 'Too few - no redundancy (aim for 2-4)' } elseif ($members.Count -ge 5) { 'Too many (aim for 2-4)' } else { 'OK (2-4 recommended)' }
        Add-Finding 'Entra' 'Global Administrator count' $st ("{0} (recommended 2-4)" -f $members.Count) `
            'Keep 2 break-glass accounts plus a few named admins; use least-privilege roles for everyone else.' 'Free'
        Set-LastFindingItems $upns 0
    }
    elseif ($members.Count -gt 5) {
        $st = 'WARN'; $text = 'More than 5 holders - review'
        Add-Finding 'Entra' ("{0} count" -f $rd.Name) WARN ("{0} members" -f $members.Count) 'Review: many holders of a high-privilege role.' 'Free'
        Set-LastFindingItems $upns 0
    }
    else { $st = 'PASS'; $text = if ($note) { $note } elseif ($members.Count -eq 0) { 'No active members' } else { 'OK' } }

    $script:RoleRows.Add([pscustomobject]@{ Role = $rd.Name; Tier = $rd.Tier; Count = $members.Count; Users = $upns; Other = $other; Status = $st; Note = $text })

    $tierCol = switch ($rd.Tier) { 'Critical' { 'Magenta' } 'High' { 'Yellow' } default { 'Gray' } }
    $stCol   = switch ($st) { 'FAIL' { 'Red' } 'WARN' { 'Yellow' } default { 'Green' } }
    if ($members.Count -gt 0 -or $rd.Tier -eq 'Critical' -or $script:Detailed) {
        Write-Host ("    {0,-42} " -f $rd.Name) -NoNewline
        Write-Host ("{0,-9} " -f $rd.Tier) -ForegroundColor $tierCol -NoNewline
        Write-Host ("{0,7}   " -f $members.Count) -ForegroundColor White -NoNewline
        Write-Host $text -ForegroundColor $stCol
        if ($rd.Tier -eq 'Critical' -and $upns.Count) {
            $show = $upns -join ', '
            if ($other) { $show += "  [+$other non-user principal(s)]" }
            Write-Host ("      members: {0}" -f $show) -ForegroundColor DarkGray
        }
    }
}
Add-Finding 'Entra' 'Unique users holding a listed admin role' INFO ("{0} user(s)" -f $allPriv.Count)
Write-Host '    Roles with no active members are not listed. Active assignments only - PIM-eligible assignments are not included.' -ForegroundColor DarkGray

Write-SubSection 'SharePoint & OneDrive tenant settings'
Invoke-Safe 'SharePoint' 'SharePoint settings' {
    $sps = Get-GraphAll 'v1.0/admin/sharepoint/settings'
    Add-Finding 'SharePoint' 'Apps that do not use modern authentication' $(if ($sps.isLegacyAuthProtocolsEnabled) { 'FAIL' } else { 'PASS' }) `
        $(if ($sps.isLegacyAuthProtocolsEnabled) { 'ALLOWED (legacy authentication protocols enabled)' } else { 'Blocked' }) `
        'SharePoint admin center > Policies > Access control > Apps that do not use modern authentication > Block access.' 'Any'
    $cap = "$($sps.sharingCapability)"
    $capTxt = switch ($cap) {
        'disabled'                       { 'Only people in your organization' }
        'existingExternalUserSharingOnly' { 'Existing guests only' }
        'externalUserSharingOnly'        { 'New and existing guests' }
        'externalUserAndGuestSharing'    { 'Anyone (anonymous links allowed)' }
        default                          { $cap }
    }
    $capSt = switch ($cap) {
        'disabled'                       { 'PASS' }
        'existingExternalUserSharingOnly' { 'PASS' }
        'externalUserAndGuestSharing'    { 'WARN' }
        default                          { 'INFO' }
    }
    Add-Finding 'SharePoint' 'External sharing level' $capSt $capTxt 'Limit to existing guests, or new and existing guests, unless anonymous links are truly required.' 'Any'
}


# ----------------------------------------------------------------------------------------
#  5. INTUNE
# ----------------------------------------------------------------------------------------
Write-Section '5' 'Microsoft Intune - device management'

Write-SubSection 'Licensing & service status'
$intuneSkus = @($activePlans | Where-Object { $_.Plan -like 'INTUNE_A*' } | ForEach-Object { if ($friendly[$_.Sku]) { $friendly[$_.Sku] } else { $_.Sku } } | Select-Object -Unique)
if ($Lic.Intune) {
    Add-Finding 'Intune' 'Intune license' PASS ("Licensed via: " + ($intuneSkus -join ', '))
}
else {
    Add-Finding 'Intune' 'Intune license' NOLIC 'Not licensed - Intune is not enabled for this tenant' `
        'Intune Plan 1 is included in M365 Business Premium, E3, E5 and EMS.' 'Intune Plan 1'
}

$script:intuneActive = $false
$script:cpCount = 0
$script:mamCount = 0
if ($Lic.Intune) {
    Invoke-Safe 'Intune' 'Intune service state' {
        $dm = Get-GraphAll 'v1.0/deviceManagement'
        $script:intuneActive = ($dm.subscriptionState -eq 'active')
        Add-Finding 'Intune' 'Intune service state' $(if ($script:intuneActive) { 'PASS' } else { 'WARN' }) ("subscriptionState = {0}" -f $dm.subscriptionState) `
            'Licensed but Intune is not active - complete Intune setup / MDM authority in the Intune admin center.'
    }
}
else {
    Add-Finding 'Intune' 'Intune service state' INFO 'Skipped - not licensed'
}

if ($Lic.Intune) {
    Write-SubSection 'Enrolled devices' -Now
    Invoke-Safe 'Intune' 'Managed devices' {
        $dev = @(Get-GraphAll 'v1.0/deviceManagement/managedDevices?$select=id,operatingSystem,complianceState,deviceName&$top=999')
        if ($dev.Count -eq 0) {
            Add-Finding 'Intune' 'Enrolled devices' WARN '0 devices - Intune is licensed but not in use' 'Enroll devices or use app protection (MAM) policies.'
        }
        else {
            Add-Finding 'Intune' 'Enrolled devices' INFO ("{0} device(s)" -f $dev.Count)
            Write-Host ("    {0} enrolled: {1}" -f $dev.Count, ((@($dev | Group-Object operatingSystem | Sort-Object Count -Descending) | ForEach-Object { "{0} {1}" -f $_.Name, $_.Count }) -join '   |   ')) -ForegroundColor Gray
            $comp = @($dev | Where-Object complianceState -eq 'compliant').Count
            $script:IntuneData = [pscustomobject]@{ Total = $dev.Count; CompliantPct = (100 * $comp / $dev.Count); OS = @($dev | Group-Object operatingSystem | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count } }) }
            $non  = @($dev | Where-Object complianceState -eq 'noncompliant').Count
            Write-Host ''
            Write-Bar (100 * $comp / $dev.Count) 'Compliant devices'
            Add-Finding 'Intune' 'Non-compliant devices' $(if ($non) { 'WARN' } else { 'PASS' }) ("{0} non-compliant, {1} unknown/other" -f $non, ($dev.Count - $comp - $non)) 'Investigate non-compliant devices; CA grants may block them.'
            Set-LastFindingItems @($dev | Where-Object complianceState -eq 'noncompliant' | ForEach-Object { "$($_.deviceName)  ($($_.operatingSystem))" }) 10
        }
    }

    Write-SubSection 'Policies'
    Invoke-Safe 'Intune' 'Compliance policies' {
        $cp = @(Get-GraphAll 'v1.0/deviceManagement/deviceCompliancePolicies?$select=id,displayName')
        $script:cpCount = $cp.Count
        $script:IntunePolicies = @($cp | Sort-Object displayName | ForEach-Object { $_.displayName })
        Add-Finding 'Intune' 'Device compliance policies' $(if ($cp.Count) { 'PASS' } else { 'WARN' }) ("{0} policy(ies)" -f $cp.Count) 'Create at least one compliance policy per OS in use.'
        if ($script:Detailed) { $cp | Sort-Object displayName | ForEach-Object { Write-Host ("            * {0}" -f $_.displayName) -ForegroundColor Gray } }
    }
    Invoke-Safe 'Intune' 'Configuration profiles' {
        $cfg = @(Get-GraphAll 'v1.0/deviceManagement/deviceConfigurations?$select=id,displayName')
        $cat = 0; try { $cat = @(Get-GraphAll 'beta/deviceManagement/configurationPolicies?$select=id,name').Count } catch { }
        Add-Finding 'Intune' 'Configuration profiles' INFO ("{0} template profile(s), {1} settings-catalog policy(ies)" -f $cfg.Count, $cat)
    }
    Invoke-Safe 'Intune' 'App protection' {
        $ios = @(Get-GraphAll 'v1.0/deviceAppManagement/iosManagedAppProtections?$select=id').Count
        $and = @(Get-GraphAll 'v1.0/deviceAppManagement/androidManagedAppProtections?$select=id').Count
        $script:mamCount = $ios + $and
        Add-Finding 'Intune' 'App protection (MAM) policies' $(if ($script:mamCount) { 'PASS' } else { 'INFO' }) ("iOS: {0}   Android: {1}" -f $ios, $and)
    }

    Write-SubSection 'Cross-check: Conditional Access vs. Intune'
    $needCompliant = @($CAOn | Where-Object { $_.grantControls.builtInControls -contains 'compliantDevice' })
    $needAppProt   = @($CAOn | Where-Object { $_.grantControls.builtInControls -contains 'compliantApplication' })
    if ($needCompliant.Count) {
        if ($script:cpCount -eq 0 -or -not $script:intuneActive) {
            Add-Finding 'Intune' 'CA requires compliant device' FAIL ("{0} CA policy(ies) require it, but Intune has no usable compliance policy" -f $needCompliant.Count) `
                'Users will be locked out. Create compliance policies / enroll devices first.'
        }
        else { Add-Finding 'Intune' 'CA requires compliant device' PASS ("{0} CA policy(ies) backed by {1} compliance policy(ies)" -f $needCompliant.Count, $script:cpCount) }
    }
    else { Add-Finding 'Intune' 'CA requires compliant device' INFO 'No enforced CA policy uses the compliant-device grant' }
    if ($needAppProt.Count) {
        Add-Finding 'Intune' 'CA requires app protection policy' $(if ($script:mamCount) { 'PASS' } else { 'FAIL' }) ("{0} CA policy(ies); {1} MAM policy(ies) exist" -f $needAppProt.Count, $script:mamCount)
    }
}

# ----------------------------------------------------------------------------------------
#  3. EXCHANGE ONLINE
# ----------------------------------------------------------------------------------------
Write-Section '6' 'Exchange Online'

Write-SubSection 'Organization-level settings'
$orgCfg = $null
Invoke-Safe 'Exchange' 'Organization config' { $script:orgCfg = Get-OrganizationConfig }

if ($orgCfg) {
    Add-Finding 'Exchange' 'Organization auditing' $(if (-not $orgCfg.AuditDisabled) { 'PASS' } else { 'FAIL' }) `
        $(if (-not $orgCfg.AuditDisabled) { 'On (mailbox auditing default)' } else { 'DISABLED' }) 'Set-OrganizationConfig -AuditDisabled $false' 'Any'
    Add-Finding 'Exchange' 'Modern authentication (OAuth2)' $(if ($orgCfg.OAuth2ClientProfileEnabled) { 'PASS' } else { 'FAIL' }) `
        (Format-Bool $orgCfg.OAuth2ClientProfileEnabled) 'Set-OrganizationConfig -OAuth2ClientProfileEnabled $true' 'Any'
    Add-Finding 'Exchange' 'Customer Lockbox' INFO (Format-Bool $orgCfg.CustomerLockboxEnabled)
    if ($orgCfg.PSObject.Properties['RejectDirectSend']) {
        Add-Finding 'Exchange' 'Reject Direct Send' $(if ($orgCfg.RejectDirectSend) { 'PASS' } else { 'WARN' }) `
            (Format-Bool $orgCfg.RejectDirectSend) 'Set-OrganizationConfig -RejectDirectSend $true (after moving devices to a connector / SMTP relay).' 'Any'
    }
}

Invoke-Safe 'Exchange' 'Unified audit log' {
    $al = Get-AdminAuditLogConfig
    Add-Finding 'Exchange' 'Unified audit log ingestion' $(if ($al.UnifiedAuditLogIngestionEnabled) { 'PASS' } else { 'FAIL' }) `
        (Format-Bool $al.UnifiedAuditLogIngestionEnabled) 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' 'Any'
}

Write-SubSection 'Legacy protocols'
Invoke-Safe 'Exchange' 'SMTP AUTH' {
    $tc = Get-TransportConfig
    Add-Finding 'Exchange' 'SMTP AUTH (org-wide)' $(if ($tc.SmtpClientAuthenticationDisabled) { 'PASS' } else { 'WARN' }) `
        $(if ($tc.SmtpClientAuthenticationDisabled) { 'Disabled org-wide' } else { 'Enabled (bypasses MFA / CA)' }) `
        'Set-TransportConfig -SmtpClientAuthenticationDisabled $true, allow per-mailbox only where needed.' 'Any'
}
Invoke-Safe 'Exchange' 'POP/IMAP' {
    $plans = @(Get-CASMailboxPlan)
    $pop   = @($plans | Where-Object PopEnabled).Count
    $imap  = @($plans | Where-Object ImapEnabled).Count
    Add-Finding 'Exchange' 'POP3 enabled on mailbox plans' $(if ($pop) { 'WARN' } else { 'PASS' }) ("{0} of {1} plans" -f $pop, $plans.Count) `
        'Set-CASMailboxPlan <plan> -PopEnabled $false' 'Any'
    Set-LastFindingItems @($plans | Where-Object PopEnabled | ForEach-Object { "$($_.Identity)" }) 10
    Add-Finding 'Exchange' 'IMAP enabled on mailbox plans' $(if ($imap) { 'WARN' } else { 'PASS' }) ("{0} of {1} plans" -f $imap, $plans.Count) `
        'Set-CASMailboxPlan <plan> -ImapEnabled $false' 'Any'
    Set-LastFindingItems @($plans | Where-Object ImapEnabled | ForEach-Object { "$($_.Identity)" }) 10
}

Write-SubSection 'Forwarding & mail flow'
Invoke-Safe 'Exchange' 'Remote domain forwarding' {
    $rd = Get-RemoteDomain -Identity Default
    Add-Finding 'Exchange' 'Default remote domain auto-forward' $(if ($rd.AutoForwardEnabled) { 'FAIL' } else { 'PASS' }) `
        (Format-Bool $rd.AutoForwardEnabled) 'Set-RemoteDomain Default -AutoForwardEnabled $false' 'Any'
}
Invoke-Safe 'Exchange' 'Outbound spam forwarding' {
    foreach ($p in @(Get-HostedOutboundSpamFilterPolicy)) {
        $st = switch ($p.AutoForwardingMode) { 'On' { 'FAIL' } default { 'PASS' } }
        $note = if ($p.AutoForwardingMode -eq 'Automatic') { 'Automatic (Microsoft-managed, blocks external forwarding)' } else { "$($p.AutoForwardingMode)" }
        Add-Finding 'Exchange' "Auto-forward mode: $($p.Name)" $st $note 'Set AutoForwardingMode to Off.' 'Any'
    }
}
$script:TR = @()
Invoke-Safe 'Exchange' 'Transport rules' {
    $script:TR = @(Get-TransportRule -ResultSize Unlimited)

    # --- external sender identification: native Outlook tag OR a transport-rule banner / subject prefix ---
    $native = $null; try { $native = (Get-ExternalInOutlook).Enabled } catch { }
    $ext    = @($script:TR | Where-Object { $_.FromScope -eq 'NotInOrganization' -and ($_.PrependSubject -or $_.ApplyHtmlDisclaimerText) })
    $extOn  = @($ext | Where-Object { $_.State -eq 'Enabled' })
    $extOff = @($ext | Where-Object { $_.State -ne 'Enabled' })
    Add-Finding 'Exchange' 'External sender identification' $(if ($native -or $extOn.Count) { 'PASS' } else { 'WARN' }) `
        ("Outlook external tag: {0} | Banner / subject rules: {1} enabled, {2} disabled" -f (OnOff $native), $extOn.Count, $extOff.Count) `
        'Turn on the native external tag (Set-ExternalInOutlook -Enabled $true) or enable a transport rule that flags mail from outside the organization.' 'Any'
    Set-LastFindingItems @($ext | ForEach-Object { "{0}  [{1}]" -f $_.Name, $_.State })

    # --- rules that bypass spam filtering (SCL -1) ---
    $bypass = @($script:TR | Where-Object { $_.SetSCL -eq -1 -and $_.State -eq 'Enabled' })
    Add-Finding 'Exchange' 'Rules that bypass spam filtering (SCL -1)' $(if ($bypass) { 'FAIL' } else { 'PASS' }) `
        $(if ($bypass) { "{0} rule(s)" -f $bypass.Count } else { 'None' }) `
        'Remove or scope tightly. These skip spam and phish filtering; a rule keyed only on a sender domain can be spoofed.' 'Any'
    Set-LastFindingItems @($bypass | ForEach-Object { "{0}   [{1}]" -f $_.Name, (Get-RuleCondText $_) })
}

Write-SubSection 'Inbound connectors (third-party gateways / partners)'
Invoke-Safe 'Exchange' 'Inbound connectors' {
    $ic = @(Get-InboundConnector | Where-Object { $_.Enabled })
    if (-not $ic.Count) { Add-Finding 'Exchange' 'Inbound connectors' INFO 'No enabled inbound connectors'; return }
    foreach ($c in $ic) {
        $ips = @($c.SenderIPAddresses | ForEach-Object { "$_" })
        $restricted = (($c.RestrictDomainsToIPAddresses -eq $true) -and $ips.Count) -or (($c.RestrictDomainsToCertificate -eq $true) -and "$($c.TlsSenderCertificateName)")
        $ef = (@($c.EFSkipIPs).Count -gt 0) -or ($c.EFSkipLastIP -eq $true) -or (@($c.EFUsers).Count -gt 0)
        $probs = @()
        if ($c.RequireTls -ne $true) { $probs += 'TLS is not required (enable "Reject messages if they are not encrypted using TLS")' }
        if (-not $restricted)        { $probs += 'Not restricted to sender IP addresses or a certificate - mail claiming to come from the connector domains is accepted from anywhere' }
        $notes = @()
        if (-not $ef -and $ips.Count) { $notes += 'Enhanced Filtering is not configured - if this connector is a third-party mail gateway, enable it so Exchange Online evaluates the real sender IP' }
        Add-Finding 'Exchange' ("Connector: {0}" -f $c.Name) $(if ($probs) { 'WARN' } else { 'PASS' }) `
            ("{0} | TLS required: {1} | Restricted to IP/cert: {2} | Enhanced Filtering: {3}" -f $c.ConnectorType, (OnOff $c.RequireTls), $(if ($restricted) { 'Yes' } else { 'No' }), $(if ($ef) { 'Configured' } else { 'Not configured' })) `
            'Require TLS and restrict the connector to the sender IPs or certificate.' 'Any'
        Set-LastFindingItems @($probs + $notes)
    }
}

Write-SubSection 'Email authentication (DKIM / SPF / DMARC)'
Invoke-Safe 'Exchange' 'Domains' {
    $domains = @(Get-AcceptedDomain | Where-Object { $_.DomainName -notlike '*.onmicrosoft.com' })
    $dkim    = @(Get-DkimSigningConfig)
    foreach ($d in $domains) {
        $dn = $d.DomainName.ToString()
        $dk = $dkim | Where-Object Domain -eq $dn
        Add-Finding 'Exchange' "DKIM: $dn" $(if ($dk.Enabled) { 'PASS' } else { 'WARN' }) $(if ($dk) { Format-Bool $dk.Enabled } else { 'No DKIM config found' }) 'Enable DKIM signing for this domain.' 'Any'
        if (-not $SkipDns -and (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
            $txt  = @(Resolve-DnsName $dn -Type TXT -ErrorAction SilentlyContinue | ForEach-Object { ($_.Strings -join '') })
            $spf  = $txt | Where-Object { $_ -like 'v=spf1*' } | Select-Object -First 1
            $st   = if (-not $spf) { 'FAIL' } elseif ($spf -match '-all') { 'PASS' } elseif ($spf -match '~all') { 'WARN' } else { 'FAIL' }
            Add-Finding 'Exchange' "SPF: $dn" $st $(if ($spf) { $spfShort = ($spf -replace '\s+', ' '); $spfShort.Substring(0, [Math]::Min(48, $spfShort.Length)) } else { 'No SPF record' }) 'Publish SPF ending in -all.' 'Any'
            $dm   = @(Resolve-DnsName "_dmarc.$dn" -Type TXT -ErrorAction SilentlyContinue | ForEach-Object { ($_.Strings -join '') }) | Where-Object { $_ -like 'v=DMARC1*' } | Select-Object -First 1
            $pol  = if ($dm -match '(?:^|;)\s*p=(\w+)') { $Matches[1] } else { $null }
            $st   = switch ($pol) { 'reject' { 'PASS' } 'quarantine' { 'PASS' } 'none' { 'WARN' } default { 'FAIL' } }
            Add-Finding 'Exchange' "DMARC: $dn" $st $(if ($pol) { "p=$pol" } else { 'No DMARC record' }) 'Move to p=quarantine / p=reject with reporting.' 'Any'
        }
    }
}

if ($ScanMailboxes) {
    Write-SubSection 'Mailbox scan (-ScanMailboxes)'
    Invoke-Safe 'Exchange' 'Mailbox forwarding' {
        $fwd = @(Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress, ForwardingAddress |
                 Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })
        Add-Finding 'Exchange' 'Mailboxes with forwarding configured' $(if ($fwd) { 'WARN' } else { 'PASS' }) ("{0} mailbox(es)" -f $fwd.Count) `
            'Review each: attackers use forwarding for persistence/exfil.' 'Any'
        Set-LastFindingItems @($fwd | ForEach-Object { "{0} -> {1}" -f $_.UserPrincipalName, $(if ($_.ForwardingSmtpAddress) { $_.ForwardingSmtpAddress } else { $_.ForwardingAddress }) }) 10
    }
    Invoke-Safe 'Exchange' 'Audit bypass' {
        $by = @(Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object AuditBypassEnabled)
        Add-Finding 'Exchange' 'Accounts with mailbox audit bypass' $(if ($by) { 'FAIL' } else { 'PASS' }) ("{0} account(s)" -f $by.Count) `
            'Set-MailboxAuditBypassAssociation <id> -AuditBypassEnabled $false' 'Any'
        Set-LastFindingItems @($by | ForEach-Object { "$($_.Name)" }) 10
    }
}

# ----------------------------------------------------------------------------------------
#  4. DEFENDER (EOP / MDO)
# ----------------------------------------------------------------------------------------
Write-Section '7' 'Microsoft Defender - email & collaboration policies'

Write-SubSection 'Preset security policies'
Invoke-Safe 'Defender' 'Preset policies' {
    $eop = @(Get-EOPProtectionPolicyRule)
    foreach ($n in 'Standard Preset Security Policy', 'Strict Preset Security Policy') {
        $r = $eop | Where-Object Name -eq $n
        $on = $r -and $r.State -eq 'Enabled'
        $st = if ($on) { 'PASS' } elseif ($n -like 'Standard*') { 'FAIL' } else { 'INFO' }
        Add-Finding 'Defender' ("EOP: " + ($n -replace ' Security Policy', '')) $st $(if ($r) { "$($r.State)" } else { 'Not configured' }) `
            'Turn on Standard (all users) and Strict (executives/admins) in the Defender portal.' 'Any'
    }
}
if ($Lic.MDO1) {
    Invoke-Safe 'Defender' 'MDO preset policies' {
        $atp = @(Get-ATPProtectionPolicyRule)
        foreach ($n in 'Standard Preset Security Policy', 'Strict Preset Security Policy') {
            $r = $atp | Where-Object Name -eq $n
            $on = $r -and $r.State -eq 'Enabled'
            $st = if ($on) { 'PASS' } elseif ($n -like 'Standard*') { 'FAIL' } else { 'INFO' }
            Add-Finding 'Defender' ("MDO: " + ($n -replace ' Security Policy', '')) $st $(if ($r) { "$($r.State)" } else { 'Not configured' }) `
                'Apply Defender for Office 365 protection to all recipients.' 'MDO P1'
        }
    }
}
else {
    Add-Finding 'Defender' 'Defender for Office 365 presets / Safe Links / Safe Attachments' NOLIC 'Not available - EOP only' `
        'Add Defender for Office 365 P1 (included in M365 Business Premium / E5).' 'MDO P1'
}

Write-SubSection 'Anti-phishing (default policy)'
Invoke-Safe 'Defender' 'Anti-phish' {
    $ap = Get-AntiPhishPolicy | Where-Object { $_.IsDefault -or $_.Name -like 'Office365 AntiPhish Default*' } | Select-Object -First 1
    Add-Finding 'Defender' 'Spoof intelligence' $(if ($ap.EnableSpoofIntelligence) { 'PASS' } else { 'FAIL' }) (Format-Bool $ap.EnableSpoofIntelligence) 'Enable.' 'Any'
    Add-Finding 'Defender' 'Honor sender DMARC policy' $(if ($ap.HonorDmarcPolicy) { 'PASS' } else { 'WARN' }) (Format-Bool $ap.HonorDmarcPolicy) 'Enable.' 'Any'

    $spoofBad = @()
    if ("$($ap.DmarcQuarantineAction)" -and "$($ap.DmarcQuarantineAction)" -ne 'Quarantine') { $spoofBad += "DMARC p=quarantine failures: $($ap.DmarcQuarantineAction) (recommended: Quarantine)" }
    if ("$($ap.DmarcRejectAction)" -and "$($ap.DmarcRejectAction)" -notin 'Reject', 'Quarantine') { $spoofBad += "DMARC p=reject failures: $($ap.DmarcRejectAction) (recommended: Reject)" }
    if ("$($ap.AuthenticationFailAction)" -and "$($ap.AuthenticationFailAction)" -notin 'MoveToJmf', 'Quarantine') { $spoofBad += "Spoofed messages: $($ap.AuthenticationFailAction) (recommended: Junk or Quarantine)" }
    Add-Finding 'Defender' 'Spoof / DMARC actions' $(if ($spoofBad) { 'WARN' } else { 'PASS' }) `
        ("DMARC quarantine: {0} | DMARC reject: {1} | Spoofed: {2}" -f $ap.DmarcQuarantineAction, $ap.DmarcRejectAction, $ap.AuthenticationFailAction) `
        'Quarantine p=quarantine failures, reject p=reject failures, and send other spoofed mail to Junk or Quarantine.' 'Any'
    Set-LastFindingItems $spoofBad

    $tipsOff = @()
    if ($ap.EnableFirstContactSafetyTips -ne $true) { $tipsOff += 'First contact safety tip is off' }
    if ($ap.EnableUnauthenticatedSender -ne $true)  { $tipsOff += "Unauthenticated sender '?' symbol is off" }
    if ($ap.EnableViaTag -ne $true)                 { $tipsOff += '"via" tag is off' }
    Add-Finding 'Defender' 'Spoof safety tips' $(if ($tipsOff) { 'WARN' } else { 'PASS' }) `
        ("First contact tip: {0} | '?' symbol: {1} | via tag: {2}" -f (OnOff $ap.EnableFirstContactSafetyTips), (OnOff $ap.EnableUnauthenticatedSender), (OnOff $ap.EnableViaTag)) `
        'Turn on all three so users can spot first-time and unauthenticated senders.' 'Any'
    Set-LastFindingItems $tipsOff

    Add-Finding 'Defender' 'Phish threshold level (1-4)' $(if ($ap.PhishThresholdLevel -ge 2) { 'PASS' } else { 'WARN' }) "$($ap.PhishThresholdLevel)" 'Standard uses 2, Strict uses 3.' 'Any'
    if ($Lic.MDO1) {
        $imp = @()
        if (-not $ap.EnableTargetedUserProtection)       { $imp += 'User impersonation protection is off (protect executives / finance, up to 350 users)' }
        if (-not $ap.EnableOrganizationDomainsProtection) { $imp += 'Domain impersonation protection is off (protect your own domains)' }
        if (-not $ap.EnableMailboxIntelligenceProtection) { $imp += 'Mailbox intelligence protection is off' }
        Add-Finding 'Defender' 'Impersonation protection' $(if ($imp) { 'WARN' } else { 'PASS' }) `
            ("Users: {0} | Domains: {1} | Mailbox intelligence: {2}" -f (OnOff $ap.EnableTargetedUserProtection), (OnOff $ap.EnableOrganizationDomainsProtection), (OnOff $ap.EnableMailboxIntelligenceProtection)) `
            'Turn on user, domain and mailbox-intelligence impersonation protection.' 'MDO P1'
        Set-LastFindingItems $imp
    }
    else {
        Add-Finding 'Defender' 'Impersonation protection' NOLIC 'Not enforced - requires Defender for Office 365' '' 'MDO P1'
    }
}

Write-SubSection 'Anti-spam (default policy)'
Invoke-Safe 'Defender' 'Anti-spam' {
    $sp = Get-HostedContentFilterPolicy | Where-Object { $_.IsDefault } | Select-Object -First 1
    $bt = [int]$sp.BulkThreshold
    Add-Finding 'Defender' 'Bulk complaint level (BCL) threshold' $(if ($bt -le $Baseline.BulkThreshold) { 'PASS' } else { 'WARN' }) `
        ("{0}  (Microsoft default 7; Standard preset 6; Strict 5)" -f $bt) ("Lower to {0} or less." -f $Baseline.BulkThreshold) 'Any'

    $acts = @(
        @{ N = 'Spam';                  V = "$($sp.SpamAction)";                 OK = @('MoveToJmf', 'Quarantine'); Sev = 'WARN' }
        @{ N = 'High-confidence spam';  V = "$($sp.HighConfidenceSpamAction)";   OK = @('MoveToJmf', 'Quarantine'); Sev = 'WARN' }
        @{ N = 'Phish';                 V = "$($sp.PhishSpamAction)";            OK = @('MoveToJmf', 'Quarantine'); Sev = 'WARN' }
        @{ N = 'High-confidence phish'; V = "$($sp.HighConfidencePhishAction)";  OK = @('Quarantine');              Sev = 'FAIL' }
    )
    $bad = @(); $sev = 'PASS'
    foreach ($a in $acts) {
        if ($a.V -notin $a.OK) {
            $bad += ("{0} action is {1} (expected: {2})" -f $a.N, $a.V, ($a.OK -join ' or '))
            if ($a.Sev -eq 'FAIL') { $sev = 'FAIL' } elseif ($sev -ne 'FAIL') { $sev = 'WARN' }
        }
    }
    Add-Finding 'Defender' 'Spam / phish actions' $sev `
        ("Spam: {0} | High-conf spam: {1} | Phish: {2} | High-conf phish: {3}" -f $sp.SpamAction, $sp.HighConfidenceSpamAction, $sp.PhishSpamAction, $sp.HighConfidencePhishAction) `
        'High-confidence phish must be quarantined; other verdicts should go to Junk or Quarantine.' 'Any'
    Set-LastFindingItems $bad

    $tag = "$($sp.HighConfidencePhishQuarantineTag)"
    Add-Finding 'Defender' 'Quarantine policy: high-confidence phish' $(if (-not $tag) { 'INFO' } elseif ($tag -eq 'AdminOnlyAccessPolicy') { 'PASS' } else { 'WARN' }) `
        $(if ($tag) { $tag } else { 'Not reported' }) 'Use AdminOnlyAccessPolicy so users cannot release high-confidence phish themselves.' 'Any'

    Add-Finding 'Defender' 'Zero-hour auto purge (spam / phish)' $(if ($sp.SpamZapEnabled -and $sp.PhishZapEnabled) { 'PASS' } else { 'FAIL' }) `
        ("{0} / {1}" -f (Format-Bool $sp.SpamZapEnabled), (Format-Bool $sp.PhishZapEnabled)) 'Enable both.' 'Any'

    $other = @()
    if ("$($sp.IntraOrgFilterState)" -eq 'Disabled') { $other += 'Anti-spam filtering for messages between internal users is disabled' }
    $ret = [int]$sp.QuarantineRetentionPeriod
    if ($ret -gt 0 -and $ret -lt $Baseline.QuarantineRetentionDays) { $other += ("Quarantine retention is {0} days (expected at least {1})" -f $ret, $Baseline.QuarantineRetentionDays) }
    if ($sp.InlineSafetyTipsEnabled -ne $true) { $other += 'Spam safety tips are off' }
    Add-Finding 'Defender' 'Other anti-spam settings' $(if ($other) { 'WARN' } else { 'PASS' }) `
        ("Internal-sender filtering: {0} | Quarantine retention: {1} days | Safety tips: {2}" -f $sp.IntraOrgFilterState, $ret, (OnOff $sp.InlineSafetyTipsEnabled)) `
        'Keep internal-sender filtering on (high-confidence phish), retain quarantined mail at least 15 days and show safety tips.' 'Any'
    Set-LastFindingItems $other

    $asfText = @(
        ('Numeric IP in URL: {0}'    -f $(if ($sp.IncreaseScoreWithNumericIps) { $sp.IncreaseScoreWithNumericIps } else { 'n/a' }))
        ('Redirect to other port: {0}' -f $(if ($sp.IncreaseScoreWithRedirectToOtherPort) { $sp.IncreaseScoreWithRedirectToOtherPort } else { 'n/a' }))
        ('Empty messages: {0}'      -f $(if ($sp.MarkAsSpamEmptyMessages) { $sp.MarkAsSpamEmptyMessages } else { 'n/a' }))
    ) -join ' | '
    Add-Finding 'Defender' 'Advanced Spam Filter (ASF) options' INFO $asfText

    $allow = @(@($sp.AllowedSenders) + @($sp.AllowedSenderDomains) | ForEach-Object { "$_" })
    Add-Finding 'Defender' 'Allowed senders / domains (bypass filtering)' $(if ($allow.Count) { 'WARN' } else { 'PASS' }) "$($allow.Count) entries" 'Remove allow-lists; they are a favourite phishing bypass.' 'Any'
    Set-LastFindingItems $allow
}
Invoke-Safe 'Defender' 'Connection filter' {
    $cf = Get-HostedConnectionFilterPolicy -Identity Default
    $n  = @($cf.IPAllowList).Count
    Add-Finding 'Defender' 'Connection filter IP allow list' $(if ($n -or $cf.EnableSafeList) { 'WARN' } else { 'PASS' }) ("{0} IPs, safe list: {1}" -f $n, (Format-Bool $cf.EnableSafeList)) 'IP allow-lists skip spam filtering; keep empty.' 'Any'
    Set-LastFindingItems @($cf.IPAllowList | ForEach-Object { "$_" }) 10
}

Write-SubSection 'Anti-malware (default policy)'
Invoke-Safe 'Defender' 'Anti-malware' {
    $mw = Get-MalwareFilterPolicy | Where-Object { $_.IsDefault } | Select-Object -First 1
    Add-Finding 'Defender' 'Common attachment types filter' $(if ($mw.EnableFileFilter) { 'PASS' } else { 'FAIL' }) (Format-Bool $mw.EnableFileFilter) 'Enable.' 'Any'
    Add-Finding 'Defender' 'Malware zero-hour auto purge' $(if ($mw.ZapEnabled) { 'PASS' } else { 'FAIL' }) (Format-Bool $mw.ZapEnabled) 'Enable.' 'Any'
    $mwBad = @()
    $mtag = "$($mw.QuarantineTag)"
    if ($mtag -and $mtag -ne 'AdminOnlyAccessPolicy') { $mwBad += "Quarantine policy is $mtag (recommended: AdminOnlyAccessPolicy)" }
    if (-not $mw.EnableInternalSenderAdminNotifications) { $mwBad += 'Admin notification for malware from internal senders is off' }
    elseif (-not "$($mw.InternalSenderAdminAddress)")    { $mwBad += 'Admin notification is on but no admin address is set' }
    Add-Finding 'Defender' 'Malware policy: quarantine & notifications' $(if ($mwBad) { 'WARN' } else { 'PASS' }) `
        ("Quarantine policy: {0} | File-type action: {1} | Admin notification: {2}" -f $mtag, $mw.FileTypeAction, (OnOff $mw.EnableInternalSenderAdminNotifications)) `
        'Use an admin-only quarantine policy and make sure someone receives the admin notifications.' 'Any'
    Set-LastFindingItems $mwBad
}

Write-SubSection 'Quarantine policies'
Invoke-Safe 'Defender' 'Quarantine policies' {
    $qp = @(Get-QuarantinePolicy)
    $qItems = @()
    foreach ($q in $qp) {
        $ep = $q.EndUserQuarantinePermissions
        if ($ep -and $ep.PSObject.Properties['PermissionToRelease']) { $rel = [bool]$ep.PermissionToRelease; $req = [bool]$ep.PermissionToRequestRelease }
        else { $t = "$ep"; $rel = [bool]($t -match 'PermissionToRelease\W+True'); $req = [bool]($t -match 'PermissionToRequestRelease\W+True') }
        $qItems += ("{0}  -  user can release: {1}, can request release: {2}" -f $q.Name, $(if ($rel) { 'Yes' } else { 'No' }), $(if ($req) { 'Yes' } else { 'No' }))
    }
    Add-Finding 'Defender' 'Quarantine policies (user permissions)' INFO ("{0} policy(ies)" -f $qp.Count)
    Set-LastFindingItems $qItems 0
}

Write-SubSection 'Filter bypasses (allow lists & overrides)'
Invoke-Safe 'Defender' 'Allowed spoofed senders' {
    $spoof = @(Get-TenantAllowBlockListSpoofItems | Where-Object { $_.Action -eq 'Allow' })
    $sItems = @($spoof | ForEach-Object { "{0}  via  {1}  ({2}){3}" -f $_.SpoofedUser, $_.SendingInfrastructure, $_.SpoofType, $(if ("$($_.SpoofedUser)" -eq '*') { '  - wildcard user' } else { '' }) })
    Add-Finding 'Defender' 'Allowed spoofed senders (Tenant Allow/Block List)' $(if ($spoof.Count) { 'WARN' } else { 'PASS' }) ("{0} entry(ies)" -f $spoof.Count) `
        'Each entry lets spoofed mail through. Keep only entries you can justify and review them regularly.' 'Any'
    Set-LastFindingItems $sItems
}
Invoke-Safe 'Defender' 'Tenant allow entries' {
    $counts = @(); $noExp = 0; $aItems = @()
    foreach ($lt in 'Sender', 'Url', 'FileHash', 'IP') {
        $e = @()
        try { $e = @(Get-TenantAllowBlockListItems -ListType $lt -Allow -ErrorAction Stop) } catch { }
        $counts += ("{0}: {1}" -f $lt, $e.Count)
        foreach ($x in $e) {
            $never = ($x.NoExpiration -eq $true) -or (-not $x.ExpirationDate)
            if ($never) { $noExp++ }
            $aItems += ("[{0}] {1}  ({2})" -f $lt, $x.Value, $(if ($never) { 'never expires' } else { 'expires ' + ([datetime]$x.ExpirationDate).ToString('yyyy-MM-dd') }))
        }
    }
    Add-Finding 'Defender' 'Tenant allow-list entries' $(if ($noExp) { 'WARN' } elseif ($aItems.Count) { 'INFO' } else { 'PASS' }) ($counts -join ' | ') `
        'Allow entries that never expire keep bypassing filtering. Set expirations and review them.' 'Any'
    Set-LastFindingItems $aItems
}
Invoke-Safe 'Defender' 'Advanced Delivery' {
    $dItems = @(); $n1 = 0; $n2 = 0
    foreach ($r in @(Get-ExoPhishSimOverrideRule)) { $n1++; $dItems += ("Phishing simulation: domains {0}; IPs {1}" -f (@($r.Domains) -join ', '), (@($r.SenderIpRanges) -join ', ')) }
    foreach ($r in @(Get-ExoSecOpsOverrideRule))   { $n2++; $dItems += ("SecOps mailbox: {0}" -f (@($r.SentTo) -join ', ')) }
    Add-Finding 'Defender' 'Advanced Delivery overrides' INFO ("Phishing simulation rules: {0} | SecOps mailbox rules: {1}" -f $n1, $n2)
    Set-LastFindingItems $dItems 0
}

Write-SubSection 'Safe Links / Safe Attachments (Defender for Office 365)'
if ($Lic.MDO1) {
    Invoke-Safe 'Defender' 'Safe Links' {
        $sl = @(Get-SafeLinksPolicy)
        if ($sl.Count -eq 0) {
            Add-Finding 'Defender' 'Safe Links policies' WARN 'None - only Built-in protection applies' 'Apply Standard/Strict preset or create a policy for all users.' 'MDO P1'
        }
        foreach ($p in $sl) {
            $ok = $p.EnableSafeLinksForEmail -and $p.EnableSafeLinksForTeams -and $p.ScanUrls -and -not $p.DisableUrlRewrite
            Add-Finding 'Defender' "Safe Links: $($p.Name)" $(if ($ok) { 'PASS' } else { 'WARN' }) `
                ("Email:{0} Teams:{1} Scan:{2} Rewrite:{3}" -f $p.EnableSafeLinksForEmail, $p.EnableSafeLinksForTeams, $p.ScanUrls, (-not $p.DisableUrlRewrite)) 'Enable email + Teams, real-time scan, URL rewrite.' 'MDO P1'
        }
    }
    Invoke-Safe 'Defender' 'Safe Attachments' {
        $sa = @(Get-SafeAttachmentPolicy)
        if ($sa.Count -eq 0) {
            Add-Finding 'Defender' 'Safe Attachments policies' WARN 'None - only Built-in protection applies' 'Apply Standard/Strict preset or create a policy for all users.' 'MDO P1'
        }
        foreach ($p in $sa) {
            Add-Finding 'Defender' "Safe Attachments: $($p.Name)" $(if ($p.Enable -and $p.Action -eq 'Block') { 'PASS' } else { 'WARN' }) ("Enabled:{0} Action:{1}" -f $p.Enable, $p.Action) 'Enable with action = Block.' 'MDO P1'
        }
        $atpO = Get-AtpPolicyForO365
        Add-Finding 'Defender' 'Safe Attachments for SPO / OneDrive / Teams' $(if ($atpO.EnableATPForSPOTeamsODB) { 'PASS' } else { 'FAIL' }) (Format-Bool $atpO.EnableATPForSPOTeamsODB) 'Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true' 'MDO P1'
        Add-Finding 'Defender' 'Safe Documents click-through blocked' $(if ($atpO.EnableSafeDocs -and -not $atpO.AllowSafeDocsOpen) { 'PASS' } else { 'WARN' }) ("SafeDocs:{0} AllowOpen:{1}" -f $atpO.EnableSafeDocs, $atpO.AllowSafeDocsOpen) 'Enable Safe Docs; do not allow open on verdict.' 'M365 E5 / A5'
    }
}
else {
    Add-Finding 'Defender' 'Safe Links / Safe Attachments' NOLIC 'Not licensed - features unavailable' 'Add Defender for Office 365 P1 or P2.' 'MDO P1'
}

Write-Host ''
Write-Host '  Out of scope for this script: Defender for Endpoint / Cloud Apps device policies' -ForegroundColor DarkGray
Write-Host '  (these live in Defender XDR / Intune APIs).' -ForegroundColor DarkGray

# ----------------------------------------------------------------------------------------
#  RESULTS - summary + HTML link FIRST, then the detailed output collected above
# ----------------------------------------------------------------------------------------
Close-Section
$script:Buffering = $false
Write-Progress -Id 1 -Activity 'Collecting security data' -Completed

# ---- write files quietly first (CSV + HTML) ----
$exportMsg = $null; $html = $null; $uri = $null; $htmlErr = $null; $pdfOk = $false
if ($ExportPath) {
    try {
        if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath | Out-Null }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
        $script:Findings | Select-Object Area, Check, Status, Current, Guidance, LicenseNeeded, @{ n = 'AffectedItems'; e = { @($_.Items) -join '; ' } } | Export-Csv (Join-Path $ExportPath "M365-Findings-$stamp.csv") -NoTypeInformation
        $skuRows         | Export-Csv (Join-Path $ExportPath "M365-Licensing-$stamp.csv") -NoTypeInformation
        $featureRows     | Export-Csv (Join-Path $ExportPath "M365-FeatureMatrix-$stamp.csv") -NoTypeInformation
        $exportMsg = "CSV files exported to $ExportPath"
    }
    catch { $exportMsg = "CSV export failed: $($_.Exception.Message)" }
}
$snapMsg = $null
if ($ExportConfig) {
    try {
        Write-Progress -Id 1 -Activity 'Saving configuration snapshot (JSON)'
        $sdir = $ExportPath; if (-not $sdir) { $sdir = Get-DownloadsFolder }
        if (-not (Test-Path $sdir)) { New-Item -ItemType Directory -Path $sdir | Out-Null }
        $stn  = ($script:Tenant.Name -replace '[^A-Za-z0-9]+', '-').Trim('-')
        $snapPath = Join-Path $sdir ("M365-ConfigSnapshot-{0}-{1:yyyyMMdd-HHmm}.json" -f $stn, (Get-Date))
        Export-ConfigSnapshot -Path $snapPath
        $snapMsg = "Configuration snapshot saved: $snapPath"
    }
    catch { $snapMsg = "Configuration snapshot failed: $($_.Exception.Message)" }
    Write-Progress -Id 1 -Activity 'Saving configuration snapshot (JSON)' -Completed
}
if (-not $NoHtml) {
    try {
        $dir = $ExportPath
        if (-not $dir) { $dir = Get-DownloadsFolder }
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        $tn   = ($script:Tenant.Name -replace '[^A-Za-z0-9]+', '-').Trim('-')
        $html = Join-Path $dir ("M365-Security-Report-{0}-{1:yyyyMMdd-HHmm}.html" -f $tn, (Get-Date))
        New-HtmlReport -Path $html
        if (-not $NoPdf) {
            Write-Progress -Id 1 -Activity 'Creating the PDF (headless Edge / Chrome)'
            $pdfTmp = Join-Path ([IO.Path]::GetTempPath()) ('m365-report-{0}.pdf' -f [guid]::NewGuid().ToString('N'))
            try {
                if (New-PdfFromHtml -HtmlPath $html -PdfPath $pdfTmp) {
                    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pdfTmp))
                    New-HtmlReport -Path $html -PdfBase64 $b64 -PdfName ([IO.Path]::GetFileNameWithoutExtension($html) + '.pdf')
                    $pdfOk = $true
                }
            }
            catch { }
            finally {
                Remove-Item -LiteralPath $pdfTmp -Force -ErrorAction SilentlyContinue
                Write-Progress -Id 1 -Activity 'Creating the PDF (headless Edge / Chrome)' -Completed
            }
        }
        $uri = ([System.Uri]$html).AbsoluteUri
    }
    catch { $htmlErr = $_.Exception.Message; $html = $null }
}

# ---- TOP OF RESULTS: summary ----
Write-Section '' 'Summary'
Write-Host '  Tenant : ' -NoNewline; Write-Host ("{0}  ({1})" -f $script:Tenant.Name, $script:Tenant.Domain) -ForegroundColor White
Write-Host ''
$by = $script:Findings | Group-Object Status
foreach ($st in 'FAIL', 'WARN', 'NOLIC', 'PASS', 'INFO', 'ERROR') {
    $n   = ($by | Where-Object Name -eq $st).Count
    $col = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan'; NOLIC = 'Magenta'; ERROR = 'DarkGray' }[$st]
    $lab = @{ PASS = 'Passing'; WARN = 'Warnings'; FAIL = 'Failing'; INFO = 'Informational'; NOLIC = 'Blocked by licensing'; ERROR = 'Could not read' }[$st]
    Write-Host ("  {0,-24}" -f $lab) -NoNewline
    Write-Host ("{0,4}" -f [int]$n) -ForegroundColor $col
}

# ---- HTML report link ----
if ($html) {
    Write-Host ''
    Write-Host (' ' * $script:W) -BackgroundColor DarkBlue
    Write-Host '  HTML REPORT READY  (dark SOC-style view with filters, CA policy cards and charts)'.PadRight($script:W) -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host (' ' * $script:W) -BackgroundColor DarkBlue
    Write-Host ("  Link : {0}" -f $uri) -ForegroundColor Cyan
    Write-Host ("  Path : {0}" -f $html) -ForegroundColor Gray
    Write-Host '  Tip  : Ctrl+Click the link in Windows Terminal / VS Code, or run  Invoke-Item <path>' -ForegroundColor DarkGray
    if ($pdfOk) { Write-Host '  PDF  : the "Download PDF" button in the report saves it straight to your Downloads folder' -ForegroundColor Cyan }
    elseif (-not $NoPdf) { Write-Host '  PDF  : could not be created automatically (needs Microsoft Edge or Chrome) - the button will open the print dialog instead' -ForegroundColor Yellow }
}
elseif ($htmlErr) { Write-Host ''; Write-Host ("  Could not create the HTML report: {0}" -f $htmlErr) -ForegroundColor Yellow }
if ($exportMsg) { Write-Host ("  {0}" -f $exportMsg) -ForegroundColor Cyan }
if ($snapMsg)   { Write-Host ("  {0}" -f $snapMsg) -ForegroundColor Cyan }

Write-Host ''
if (-not $script:Detailed) { Write-Host '  The console lists warnings, failures and license gaps only. Everything (incl. passing checks) is in the HTML report; use -Detailed to print it all here.' -ForegroundColor DarkGray }
$fails = @($script:Findings | Where-Object Status -eq 'FAIL')
if ($fails) {
    Write-SubSection 'Fix first (FAIL)' -Now
    $i = 1
    foreach ($f in $fails) {
        Write-Host ("  {0,2}. [{1}] {2}" -f $i, $f.Area, $f.Check) -ForegroundColor Red
        if ($f.Guidance) { Write-Host ("      {0}" -f $f.Guidance) -ForegroundColor DarkGray }
        $i++
    }
}
$nolic = @($script:Findings | Where-Object Status -eq 'NOLIC')
if ($nolic) {
    Write-SubSection 'Licensing gaps' -Now
    $nolic | ForEach-Object { Write-Host ("   - {0}  (needs {1})" -f $_.Check, $_.LicenseNeeded) -ForegroundColor Magenta }
}

# ---- DETAILED RESULTS (replayed from the buffer) ----
Write-Section '' 'Detailed results (sections 1 - 7)'
Show-Buffered

Write-Host ''
Write-Host '  Read-only run complete. No settings were changed.' -ForegroundColor DarkGray
Write-Host ''

# ---- last line of the screen: offer to open the report ----
if ($html) {
    $open = [bool]$OpenReport
    if (-not $open -and -not $NoPrompt) {
        try { $ans = Read-Host '  Open the HTML report now? (Y/N)'; $open = ($ans -eq '' -or $ans -match '^(y|yes)$') } catch { }
    }
    if ($open) { Invoke-Item $html }
}
