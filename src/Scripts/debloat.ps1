Write-Host "--- WINDOWS BLOATWARE REMOVER ---" -ForegroundColor Cyan
Write-Host "[*] Scanning for junk packages..." -ForegroundColor Yellow

$Junk = @(
    "*TikTok*",
    "*Facebook*",
    "*Instagram*",
    "*Twitter*",
    "*XboxApp*",
    "*XboxGamingOverlay*",
    "*SolitaireCollection*",
    "*BingWeather*",
    "*GetHelp*",
    "*GetStarted*",
    "*OfficeHub*",
    "*SkypeApp*",
    "*YourPhone*",
    "*ZuneMusic*",
    "*ZuneVideo*"
)

foreach ($App in $Junk) {
    $Package = Get-AppxPackage $App -ErrorAction SilentlyContinue
    if ($Package) {
        Write-Host "  [X] Removing $($Package.Name)..." -ForegroundColor Red
        $Package | Remove-AppxPackage -ErrorAction Continue
    }
}

Write-Host "`n[+] Bloatware scrub complete." -ForegroundColor Green