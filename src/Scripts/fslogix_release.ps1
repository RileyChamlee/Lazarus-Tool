param (
    [Parameter(Mandatory = $true)]
    [string]$TargetUser
)

Write-Host "--- FSLOGIX PROFILE UNLOCKER ---" -ForegroundColor Cyan
Write-Host "[*] Targeting User: $TargetUser" -ForegroundColor Yellow

# 1. FORCE LOGOFF
# We try to find the session ID and kick them out first
$Session = query user $TargetUser 2>$null
if ($Session) {
    # Parse the Session ID from the "query user" output
    # Output is usually: " USERNAME  SESSIONNAME  ID  STATE  IDLE TIME  LOGON TIME "
    $Lines = $Session -split "`n"
    if ($Lines.Count -ge 2) {
        # We assume the ID is the numerical digits found in the string
        try {
            $LineParts = $Lines[1] -split "\s+"
            # Usually the ID is the 3rd or 4th item depending on if SESSIONNAME is active
            $SessionId = $LineParts | Where-Object { $_ -match "^\d+$" } | Select-Object -First 1
            
            if ($SessionId) {
                Write-Host "    [+] Found Session ID: $SessionId. forcing logoff..." -ForegroundColor Green
                logoff $SessionId
                Start-Sleep -Seconds 3
            }
        }
        catch {}
    }
}
else {
    Write-Host "    [*] User does not have an active session (Disconnected/Ghost)." -ForegroundColor Gray
}

# 2. KILL ZOMBIE PROCESSES
# This is critical on Terminal Servers. If Outlook is stuck in the background, the VHDX won't detach.
Write-Host "[*] Hunting for zombie processes..." -ForegroundColor Yellow

try {
    # Get-Process -IncludeUserName requires Admin
    $Zombies = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -match $TargetUser }
    
    if ($Zombies) {
        foreach ($Proc in $Zombies) {
            Write-Host "    [X] Killing stuck process: $($Proc.Name) (PID: $($Proc.Id))" -ForegroundColor Red
            Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-Host "    [+] No stuck processes found." -ForegroundColor Green
    }
}
catch {
    Write-Host "    [!] Error scanning processes (Run Lazarus as Admin)." -ForegroundColor Red
}

# 3. RESTART FSLOGIX SERVICE?
# On a Terminal Server with other active users, we DO NOT restart the whole service.
# Killing the handles above is usually enough to let the VHDX detach automatically.

Write-Host "`n[DONE] User $TargetUser has been scrubbed." -ForegroundColor Green