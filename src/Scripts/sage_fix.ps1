Write-Host "--- SAGE 300 EXCEL LINK REPAIR ---" -ForegroundColor Cyan

# 1. KILL STUCK EXCEL PROCESSES
Write-Host "[*] Closing stuck Excel processes..." -ForegroundColor Yellow
Stop-Process -Name "excel" -ErrorAction SilentlyContinue

# 2. CLEAR CRYSTAL REPORTS TEMP FILES
Write-Host "[*] Clearing Crystal Reports temp files..." -ForegroundColor Yellow
$TempPath = "$env:TEMP"
Get-ChildItem -Path $TempPath -Filter "*.rpt" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem -Path $TempPath -Filter "CMD*" -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force

# 3. ADD TRUSTED LOCATIONS
Write-Host "[*] Injecting Excel Trusted Locations..." -ForegroundColor Yellow

$SagePaths = @("C:\Program Files (x86)\Timberline Office", "\\*\Timberline Office")

# We look for actual installed Office versions (16.0, 15.0, etc.)
$OfficeVersions = Get-ChildItem "HKCU:\Software\Microsoft\Office" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "\d+\.0" }

foreach ($Version in $OfficeVersions) {
    $VerKey = $Version.PSChildName
    $TrustRoot = "HKCU:\Software\Microsoft\Office\$VerKey\Excel\Security\Trusted Locations"
    
    if (Test-Path $TrustRoot) {
        $Index = 0
        foreach ($SagePath in $SagePaths) {
            $Index++
            $NewKey = "$TrustRoot\SageLocation$Index"
            if (-not (Test-Path $NewKey)) {
                New-Item -Path $NewKey -Force | Out-Null
                New-ItemProperty -Path $NewKey -Name "Path" -Value $SagePath -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $NewKey -Name "AllowSubfolders" -Value 1 -PropertyType DWORD -Force | Out-Null
                New-ItemProperty -Path $NewKey -Name "Description" -Value "Sage 300 Fix" -PropertyType String -Force | Out-Null
                Write-Host "    [+] Added Trust for $SagePath (Office $VerKey)" -ForegroundColor Green
            }
        }
    }
}

Write-Host "`n[DONE] Sage Excel Link repairs applied. Please re-test." -ForegroundColor Green