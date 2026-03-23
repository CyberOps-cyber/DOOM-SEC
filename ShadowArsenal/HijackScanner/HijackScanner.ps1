<#
.SYNOPSIS
HijackScanner - DLL Hijacking and Weak Permission Scanner
Educational Proof-of-Concept

.DESCRIPTION
Scans the system PATH and running processes for:
1. Writable directories in %PATH% (Path Interception)
2. Modules loaded from writable locations (DLL Sideloading opportunities)

.EXAMPLE
.\HijackScanner.ps1
#>

Write-Host "HijackScanner - DLL Hijack & Permission Auditor" -ForegroundColor Cyan
Write-Host "-----------------------------------------------" -ForegroundColor Cyan

# 1. Check System PATH for Writable Directories
Write-Host "[*] Checking %PATH% for writable directories..." -ForegroundColor Yellow
$paths = $env:PATH -split ';'
foreach ($path in $paths) {
    if (Test-Path $path) {
        try {
            $acl = Get-Acl $path
            # Very basic check: Can the current user write?
            # In a full tool, we'd check specific AccessRules for IdentityReference matches
            $testFile = Join-Path $path "test_write_access.tmp"
            try {
                [IO.File]::Create($testFile).Close()
                Remove-Item $testFile -ErrorAction SilentlyContinue
                Write-Host "[!] WRITABLE PATH FOUND: $path" -ForegroundColor Red
            } catch {
                # Not writable
            }
        } catch {
            Write-Host "[-] Access Denied: $path" -ForegroundColor DarkGray
        }
    }
}

# 2. Check Running Processes for Non-System DLLs (Simplified)
# Note: Checking write access on every loaded module is slow.
# We will just list modules loaded from paths NOT in C:\Windows
Write-Host "`n[*] Scanning running processes for non-system loaded modules..." -ForegroundColor Yellow

$processes = Get-Process -ErrorAction SilentlyContinue
foreach ($proc in $processes) {
    try {
        foreach ($mod in $proc.Modules) {
            if ($mod.FileName -and -not ($mod.FileName.ToLower().StartsWith("c:\windows"))) {
                # Potential candidate: A DLL loaded from Program Files or User dirs
                # If that dir is writable, it's a hijack vector.
                $dir = [System.IO.Path]::GetDirectoryName($mod.FileName)
                
                # Check write access (quick test)
                $isWritable = $false
                $testFile = Join-Path $dir "test_write_access.tmp"
                try {
                    [IO.File]::Create($testFile).Close()
                    Remove-Item $testFile -ErrorAction SilentlyContinue
                    $isWritable = $true
                } catch {}

                if ($isWritable) {
                    Write-Host "[!] VULNERABLE MODULE LOAD: $($proc.Name) ($($proc.Id)) loads $($mod.FileName)" -ForegroundColor Red
                }
            }
        }
    } catch {
        # Permission denied to inspect process
    }
}

Write-Host "`n[+] Scan Complete." -ForegroundColor Green
