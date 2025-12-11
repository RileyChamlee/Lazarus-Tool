Write-Host "--- CRASH DETECTIVE REPORT ---" -ForegroundColor Cyan

# 1. Check for BSODs (BugCheck 1001) - Last 5
Write-Host "`n[*] Scanning for recent Blue Screens (System History)..." -ForegroundColor Yellow
$BSODs = Get-WinEvent -LogName System -FilterXPath "*[System[EventID=1001]]" -MaxEvents 5 -ErrorAction SilentlyContinue

if ($BSODs) {
    foreach ($evt in $BSODs) {
        Write-Host "  [$($evt.TimeCreated)] CRITICAL FAILURE" -ForegroundColor Red
        # Clean up the message to just get the error string
        $msg = $evt.Message -replace "`n", " " -replace "`r", ""
        Write-Host "  Details: $msg" -ForegroundColor Gray
    }
}
else {
    Write-Host "  [+] No Blue Screens found in recent logs." -ForegroundColor Green
}

# 2. Check for App Crashes (Event 1000) - Last 24 Hours
Write-Host "`n[*] Scanning for Application Crashes (Last 24 Hours)..." -ForegroundColor Yellow

# Filter: Event 1000 (Crash) AND occurred within the last 86400000 ms (24 hours)
$AppCrashes = Get-WinEvent -LogName Application -FilterXPath "*[System[EventID=1000] and TimeCreated[timediff(@SystemTime) <= 86400000]]" -ErrorAction SilentlyContinue

if ($AppCrashes) {
    # Group by Application Name so we don't see 50 lines for the same crash
    $Groups = $AppCrashes | Group-Object { $_.Properties[0].Value } | Sort-Object Count -Descending

    foreach ($grp in $Groups) {
        $AppName = $grp.Name
        $Count = $grp.Count
        $Example = $grp.Group[0]
        $Module = $Example.Properties[1].Value # The DLL that caused it
        
        Write-Host "  [!] $AppName crashed $Count times." -ForegroundColor Red
        Write-Host "      Culprit Module: $Module" -ForegroundColor Gray
    }
}
else {
    Write-Host "  [+] No Application crashes found today." -ForegroundColor Green
}