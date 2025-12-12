Write-Host "--- BROWSER DEEP CLEAN ---" -ForegroundColor Cyan

# 1. KILL BROWSERS (Required to delete cache files)
Write-Host "[*] Closing browsers..." -ForegroundColor Yellow
Stop-Process -Name "chrome" -ErrorAction SilentlyContinue
Stop-Process -Name "msedge" -ErrorAction SilentlyContinue
Stop-Process -Name "firefox" -ErrorAction SilentlyContinue
Stop-Process -Name "brave" -ErrorAction SilentlyContinue

# 2. DEFINE PATHS
$Targets = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Code Cache",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache",
    "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*\cache2",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache"
)

# 3. PURGE
foreach ($Path in $Targets) {
    if (Test-Path $Path) {
        Write-Host "    Cleaning: $Path" -ForegroundColor Gray
        Remove-Item -Path "$Path\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n[DONE] Browsers scrubbed." -ForegroundColor Green