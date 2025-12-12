Write-Host "--- BLOATWARE ASSASSIN ---" -ForegroundColor Cyan

# List of apps to remove (Safe List)
$Bloat = @(
    "*Microsoft.3DBuilder*",
    "*Microsoft.BingNews*",
    "*Microsoft.GetHelp*",
    "*Microsoft.Getstarted*",
    "*Microsoft.Messaging*",
    "*Microsoft.MicrosoftSolitaireCollection*",
    "*Microsoft.News*",
    "*Microsoft.Office.OneNote*",
    "*Microsoft.People*",
    "*Microsoft.SkypeApp*",
    "*Microsoft.WindowsAlarms*",
    "*Microsoft.WindowsCamera*",
    "*Microsoft.windowscommunicationsapps*",
    "*Microsoft.WindowsFeedbackHub*",
    "*Microsoft.WindowsMaps*",
    "*Microsoft.WindowsSoundRecorder*",
    "*Microsoft.XboxApp*",
    "*Microsoft.XboxGamingOverlay*",
    "*Microsoft.XboxIdentityProvider*",
    "*Microsoft.XboxSpeechToTextOverlay*",
    "*Microsoft.ZuneMusic*",
    "*Microsoft.ZuneVideo*"
)

Write-Host "[*] Removing Junk Apps..." -ForegroundColor Yellow

foreach ($App in $Bloat) {
    Get-AppxPackage -AllUsers $App | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $App } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    Write-Host "    [X] Removed $App" -ForegroundColor Gray
}

Write-Host "`n[DONE] System Debloated." -ForegroundColor Green