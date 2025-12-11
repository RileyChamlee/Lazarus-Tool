Write-Host "--- HARDWARE HEALTH SCANNER ---" -ForegroundColor Cyan
Write-Host "[*] Querying PnP Device Status..." -ForegroundColor Yellow

# Get devices that are NOT "OK"
$BadDevices = Get-PnpDevice | Where-Object { $_.Status -ne 'OK' }

if ($BadDevices) {
    foreach ($dev in $BadDevices) {
        Write-Host "  [!] FAULTY DEVICE DETECTED" -ForegroundColor Red
        Write-Host "      Name:   $($dev.FriendlyName)"
        Write-Host "      Status: $($dev.Status)"
        Write-Host "      Class:  $($dev.Class)"
        Write-Host "      Error:  $($dev.Problem)"
        Write-Host ""
    }
}
else {
    Write-Host "  [+] All Hardware Devices report 'OK' status." -ForegroundColor Green
}