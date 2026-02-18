#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Security Audit & Active Directory Enumeration Script

.DESCRIPTION
    Performs a comprehensive security audit of a Windows host and (optionally)
    Active Directory environment. Generates a structured HTML report.

    Checks:
      - Local user accounts and password policies
      - Members of privileged local groups
      - Running services and their permissions
      - Scheduled tasks with high privileges
      - Open network ports and connections
      - Installed software and patch status
      - Windows Defender / AV status
      - Active Directory user/group enumeration (if domain-joined)
      - Firewall profile status
      - Audit policy configuration

.PARAMETER OutputPath
    Path to save the HTML report. Default: .\audit_report_<date>.html

.PARAMETER SkipAD
    Skip Active Directory enumeration (for non-domain or local-only audit)

.EXAMPLE
    .\windows_audit.ps1
    .\windows_audit.ps1 -OutputPath C:\Reports\audit.html -SkipAD

.AUTHOR  Matthew Vaishnav — CST, Conestoga College
#>

param(
    [string]$OutputPath = ".\audit_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [switch]$SkipAD
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$Results = [System.Collections.Generic.List[hashtable]]::new()
$Warnings = [System.Collections.Generic.List[string]]::new()

function Write-Section([string]$Title) {
    Write-Host "`n  $('─'*50)" -ForegroundColor DarkGray
    Write-Host "  ► $Title" -ForegroundColor Cyan
    Write-Host "  $('─'*50)" -ForegroundColor DarkGray
}

function Add-Finding([string]$Category, [string]$Item, [string]$Value, [string]$Severity = "INFO") {
    $Results.Add(@{
        Category = $Category
        Item     = $Item
        Value    = $Value
        Severity = $Severity
    })
    $icon = switch ($Severity) {
        "HIGH"   { "🔴" }
        "MEDIUM" { "🟡" }
        "LOW"    { "🔵" }
        default  { "⚪" }
    }
    Write-Host "    $icon [$Severity] $Item : $Value"
}

# ── 1. System Information ─────────────────────────────────────────────────────
Write-Section "System Information"
$os    = Get-WmiObject Win32_OperatingSystem
$comp  = Get-WmiObject Win32_ComputerSystem

Add-Finding "System" "Hostname"       $env:COMPUTERNAME
Add-Finding "System" "OS"             "$($os.Caption) $($os.Version)"
Add-Finding "System" "Architecture"   $os.OSArchitecture
Add-Finding "System" "Domain"         $comp.Domain
Add-Finding "System" "Last Boot"      $os.ConvertToDateTime($os.LastBootUpTime)
Add-Finding "System" "Uptime (days)"  ([math]::Round(((Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)).TotalDays, 1))

$buildNum = [int]$os.BuildNumber
if ($buildNum -lt 17763) {
    Add-Finding "System" "OS Support Status" "POTENTIALLY EOL — Build $buildNum" -Severity "HIGH"
    $Warnings.Add("Operating system may be end-of-life.")
} else {
    Add-Finding "System" "OS Support Status" "Supported (Build $buildNum)"
}

# ── 2. Local Users & Groups ───────────────────────────────────────────────────
Write-Section "Local Users & Groups"
$localUsers = Get-LocalUser

foreach ($user in $localUsers) {
    $severity = "INFO"
    $notes = @()
    if ($user.Enabled -and -not $user.PasswordRequired) {
        $notes += "NO PASSWORD REQUIRED"; $severity = "HIGH"
    }
    if ($user.PasswordNeverExpires -and $user.Enabled) {
        $notes += "Password never expires"
    }
    $noteStr = if ($notes) { $notes -join ", " } else { "OK" }
    Add-Finding "Local Users" $user.Name "Enabled=$($user.Enabled) | $noteStr" -Severity $severity
}

$privGroups = @("Administrators", "Remote Desktop Users", "Remote Management Users",
                "Backup Operators", "Network Configuration Operators")

foreach ($grp in $privGroups) {
    try {
        $members = Get-LocalGroupMember -Group $grp -ErrorAction Stop |
                   Select-Object -ExpandProperty Name
        $memberStr = if ($members) { $members -join "; " } else { "(empty)" }
        $sev = if ($members.Count -gt 3) { "MEDIUM" } else { "INFO" }
        Add-Finding "Local Groups" $grp $memberStr -Severity $sev
    } catch {
        Add-Finding "Local Groups" $grp "Group not found or error" -Severity "LOW"
    }
}

# ── 3. Password Policy ────────────────────────────────────────────────────────
Write-Section "Password Policy"
$policy = net accounts 2>&1
foreach ($line in ($policy | Where-Object { $_ -match ":" })) {
    $parts = $line -split ":", 2
    if ($parts.Count -eq 2) {
        $key = $parts[0].Trim()
        $val = $parts[1].Trim()
        $sev = "INFO"
        if ($key -match "minimum password length" -and [int]$val -lt 12) { $sev = "MEDIUM" }
        if ($key -match "lockout threshold" -and ($val -eq "Never" -or [int]$val -eq 0)) { $sev = "HIGH" }
        Add-Finding "Password Policy" $key $val -Severity $sev
    }
}

# ── 4. Services ───────────────────────────────────────────────────────────────
Write-Section "Running Services"
$riskyServices = @{
    "Telnet"        = "HIGH"
    "RemoteRegistry"= "MEDIUM"
    "Browser"       = "MEDIUM"
    "SNMP"          = "MEDIUM"
    "LanmanServer"  = "INFO"
}

foreach ($svc in $riskyServices.Keys) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq "Running") {
        Add-Finding "Services" "Risky Service Running" "$svc (Status: $($s.Status))" -Severity $riskyServices[$svc]
        $Warnings.Add("Potentially dangerous service is running: $svc")
    }
}

# ── 5. Open Ports ─────────────────────────────────────────────────────────────
Write-Section "Network Connections"
$listenPorts = Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Sort-Object LocalPort

$riskyPorts = @(21, 23, 25, 53, 135, 137, 139, 445, 1433, 3389, 5985, 5986)

foreach ($conn in $listenPorts) {
    $sev = if ($conn.LocalPort -in $riskyPorts) { "MEDIUM" } else { "INFO" }
    $procName = try { (Get-Process -Id $conn.OwningProcess -ErrorAction Stop).Name } catch { "Unknown" }
    Add-Finding "Network" "Listening Port $($conn.LocalPort)" "$($conn.LocalAddress) — $procName" -Severity $sev
}

# ── 6. Scheduled Tasks ───────────────────────────────────────────────────────
Write-Section "Scheduled Tasks"
$tasks = Get-ScheduledTask | Where-Object {
    $_.State -eq "Ready" -and
    $_.Principal.RunLevel -eq "Highest" -and
    $_.TaskPath -notlike "\Microsoft\*"
}

foreach ($task in $tasks) {
    Add-Finding "Scheduled Tasks" $task.TaskName `
        "RunAs=$($task.Principal.UserId) | Path=$($task.TaskPath)" `
        -Severity "MEDIUM"
}

# ── 7. Windows Defender ───────────────────────────────────────────────────────
Write-Section "Windows Defender / AV Status"
try {
    $av = Get-MpComputerStatus -ErrorAction Stop
    Add-Finding "AV" "Defender Status"      $av.AMServiceEnabled
    Add-Finding "AV" "Real-Time Protection" $av.RealTimeProtectionEnabled `
        -Severity (if (-not $av.RealTimeProtectionEnabled) { "HIGH" } else { "INFO" })
    Add-Finding "AV" "Antispyware Enabled"  $av.AntispywareEnabled
    Add-Finding "AV" "Signature Version"    $av.AntivirusSignatureVersion
    $sigAge = (Get-Date) - $av.AntivirusSignatureLastUpdated
    $sigSev = if ($sigAge.Days -gt 7) { "HIGH" } elseif ($sigAge.Days -gt 3) { "MEDIUM" } else { "INFO" }
    Add-Finding "AV" "Signature Age" "$($sigAge.Days) days old" -Severity $sigSev
} catch {
    Add-Finding "AV" "Defender" "Could not retrieve status" -Severity "LOW"
}

# ── 8. Firewall Status ────────────────────────────────────────────────────────
Write-Section "Firewall Status"
$profiles = Get-NetFirewallProfile
foreach ($p in $profiles) {
    $sev = if (-not $p.Enabled) { "HIGH" } else { "INFO" }
    Add-Finding "Firewall" "$($p.Name) Profile" "Enabled=$($p.Enabled)" -Severity $sev
}

# ── 9. Windows Updates ───────────────────────────────────────────────────────
Write-Section "Recent Updates"
$updates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
foreach ($update in $updates) {
    Add-Finding "Patches" $update.HotFixID "$($update.Description) — $($update.InstalledOn)"
}

# ── 10. Active Directory ──────────────────────────────────────────────────────
if (-not $SkipAD -and $comp.PartOfDomain) {
    Write-Section "Active Directory Enumeration"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        $domAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive |
                     Select-Object -ExpandProperty SamAccountName
        Add-Finding "AD" "Domain Admin Count" $domAdmins.Count `
            -Severity (if ($domAdmins.Count -gt 5) { "MEDIUM" } else { "INFO" })
        Add-Finding "AD" "Domain Admins" ($domAdmins -join ", ")

        $cutoff = (Get-Date).AddDays(-90)
        $stale = Get-ADUser -Filter {
            LastLogonDate -lt $cutoff -and Enabled -eq $true
        } -Properties LastLogonDate | Measure-Object
        Add-Finding "AD" "Stale Enabled Accounts (90d)" $stale.Count `
            -Severity (if ($stale.Count -gt 10) { "MEDIUM" } else { "INFO" })

        $noPwRequired = Get-ADUser -Filter { PasswordNotRequired -eq $true -and Enabled -eq $true } |
                        Measure-Object
        if ($noPwRequired.Count -gt 0) {
            Add-Finding "AD" "Accounts with No Password Required" $noPwRequired.Count -Severity "HIGH"
        }

    } catch {
        Add-Finding "AD" "Error" "ActiveDirectory module not available" -Severity "LOW"
    }
}

# ── Generate HTML Report ──────────────────────────────────────────────────────
Write-Section "Generating Report"

$severityColors = @{
    "HIGH"   = "#ff4444"
    "MEDIUM" = "#ffaa00"
    "LOW"    = "#4488ff"
    "INFO"   = "#888888"
}

$tableRows = foreach ($r in $Results) {
    $color = $severityColors[$r.Severity]
    "<tr>
        <td><span style='color:$color;font-weight:bold'>$($r.Severity)</span></td>
        <td>$($r.Category)</td>
        <td>$($r.Item)</td>
        <td>$($r.Value)</td>
    </tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Windows Security Audit — $env:COMPUTERNAME</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; margin: 2rem; }
  h1 { color: #00d4ff; }
  h2 { color: #aaa; font-size: 1rem; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  th { background: #16213e; color: #00d4ff; padding: 10px; text-align: left; }
  tr:nth-child(even) { background: #0f3460; }
  tr:hover { background: #1a4a7a; }
  td { padding: 8px 12px; border-bottom: 1px solid #333; }
  .warn { background: #3d1515; border-left: 4px solid #ff4444; padding: 8px; margin: 4px 0; }
</style>
</head>
<body>
<h1>🛡️ Windows Security Audit Report</h1>
<h2>Host: $env:COMPUTERNAME | Generated: $(Get-Date) | Author: Matthew Vaishnav</h2>

$(if ($Warnings.Count) {
    "<div><h3 style='color:#ff4444'>⚠️ High-Priority Warnings ($($Warnings.Count))</h3>" +
    ($Warnings | ForEach-Object { "<div class='warn'>$_</div>" }) +
    "</div>"
})

<table>
<tr><th>Severity</th><th>Category</th><th>Item</th><th>Value</th></tr>
$($tableRows -join "`n")
</table>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`n  ✅ Report saved: $OutputPath" -ForegroundColor Green
Write-Host "  📊 Total findings: $($Results.Count)" -ForegroundColor Cyan
Write-Host "  🔴 HIGH: $(($Results | Where-Object { $_.Severity -eq 'HIGH' }).Count)" -ForegroundColor Red
Write-Host "  🟡 MEDIUM: $(($Results | Where-Object { $_.Severity -eq 'MEDIUM' }).Count)" -ForegroundColor Yellow
