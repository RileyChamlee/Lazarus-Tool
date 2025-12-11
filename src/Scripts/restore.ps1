# --- THIS MUST BE FIRST ---
[CmdletBinding()]
# --- 1. COMMAND-LINE PARAMETERS ---
param(
    [string]$SourceUser = $null,
    [string]$BackupRoot = $null,
    [switch]$RestoreSettings
)

# --- 2. CORE RESTORE FUNCTION ---
function Start-Restore {
    param(
        [string]$User,
        [string]$Root,
        [bool]$RestoreReg
    )
    
    Write-Host "Starting restore for $User..."
    $SourceBackupPath = Join-Path -Path $Root -ChildPath $User # e.g., D:\Backup\BryanFrancis
    
    if (-not (Test-Path -Path $SourceBackupPath)) {
        Write-Host "ERROR: Backup folder '$SourceBackupPath' not found."
        if ($pscmdlet.MyInvocation.CommandOrigin -eq 'Runspace') { Exit 1 } else { return $false }
    }
    
    # --- THIS IS THE FIX (v20) ---
    # Get the *interactive* user (e.g., "test"), not the admin
    Write-Host "Finding interactive user..."
    $LoggedInUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
    $UserName = $LoggedInUser.Split('\')[-1] # Gets "test" from "DOMAIN\test"
    Write-Host "Interactive user found: $UserName"

    # Find their real profile path from the registry
    $ProfileList = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue
    $UserProfile = ($ProfileList | Where-Object { $_.ProfileImagePath -like "*\$UserName" } | Select-Object -ExpandProperty ProfileImagePath | Select-Object -First 1)

    if (-not $UserProfile) {
        Write-Host "FATAL ERROR: Could not find profile path for $UserName in the registry. Cannot restore."
        return $false
    }
    Write-Host "Destination profile path set to: $UserProfile"
    
    # --- 1. DEFINE DESTINATION FOLDERS (NEW PC) ---
    Write-Host "Locating destination folders on new PC..."
    
    # Check if a company OneDrive folder is set up
    $OneDriveFolder = Get-ChildItem -Path $UserProfile -Directory -Filter "OneDrive*" -ErrorAction SilentlyContinue | Select-Object -First 1

    # Define local paths
    $LocalDesktop = Join-Path -Path $UserProfile -ChildPath "Desktop"
    $LocalDocuments = Join-Path -Path $UserProfile -ChildPath "Documents"
    $LocalPictures = Join-Path -Path $UserProfile -ChildPath "Pictures"

    # Check if OneDrive paths exist
    $OneDriveDesktop = if ($OneDriveFolder) { Join-Path -Path $OneDriveFolder.FullName -ChildPath "Desktop" } else { $null }
    $OneDriveDocuments = if ($OneDriveFolder) { Join-Path -Path $OneDriveFolder.FullName -ChildPath "Documents" } else { $null }
    $OneDrivePictures = if ($OneDriveFolder) { Join-Path -Path $OneDriveFolder.FullName -ChildPath "Pictures" } else { $null }

    # Set the *actual* destination path
    # If the OneDrive path exists, use it. If not, fall back to the local path.
    $DestDesktop = if (Test-Path $OneDriveDesktop) { $OneDriveDesktop } else { $LocalDesktop }
    $DestDocuments = if (Test-Path $OneDriveDocuments) { $OneDriveDocuments } else { $LocalDocuments }
    $DestPictures = if (Test-Path $OneDrivePictures) { $OneDrivePictures } else { $LocalPictures }

    Write-Host "  Desktop set to: $DestDesktop"
    Write-Host "  Documents set to: $DestDocuments"
    Write-Host "  Pictures set to: $DestPictures"

    $DestMap = @{
        "Desktop"   = $DestDesktop;
        "Documents" = $DestDocuments;
        "Pictures"  = $DestPictures;
        "Music"     = Join-Path -Path $UserProfile -ChildPath "Music";
        "Videos"    = Join-Path -Path $UserProfile -ChildPath "Videos";
        "Favorites" = Join-Path -Path $UserProfile -ChildPath "Favorites";
        "Downloads" = Join-Path -Path $UserProfile -ChildPath "Downloads";
    }

    # --- 2. DEFINE SOURCE FOLDERS (OLD PC BACKUP) ---
    Write-Host "Locating source folders in backup..."
    $SourceLocalMap = @{
        "Desktop"   = Join-Path -Path $SourceBackupPath -ChildPath "Desktop";
        "Documents" = Join-Path -Path $SourceBackupPath -ChildPath "Documents";
        "Pictures"  = Join-Path -Path $SourceBackupPath -ChildPath "Pictures";
        "Music"     = Join-Path -Path $SourceBackupPath -ChildPath "Music";
        "Videos"    = Join-Path -Path $SourceBackupPath -ChildPath "Videos";
        "Favorites" = Join-Path -Path $SourceBackupPath -ChildPath "Favorites";
        "Downloads" = Join-Path -Path $SourceBackupPath -ChildPath "Downloads";
    }
    $SourceOneDriveBackup = Get-ChildItem -Path $SourceBackupPath -Directory -Filter "OneDrive*" -ErrorAction SilentlyContinue | Select-Object -First 1
    $SourceOneDriveMap = @{}
    if ($SourceOneDriveBackup) {
        Write-Host "OneDrive backup folder found: $($SourceOneDriveBackup.Name)"
        $SourceOneDriveMap = @{
            "Desktop"   = Join-Path -Path $SourceOneDriveBackup.FullName -ChildPath "Desktop";
            "Documents" = Join-Path -Path $SourceOneDriveBackup.FullName -ChildPath "Documents";
            "Pictures"  = Join-Path -Path $SourceOneDriveBackup.FullName -ChildPath "Pictures";
        }
    }

    # --- 3. RESTORE & MERGE KNOWN FOLDERS ---
    Write-Host "Restoring and merging all known folders..."
    foreach ($key in $DestMap.Keys) {
        $Dest = $DestMap[$key]
        
        # A. Restore from the *local* backup
        if ($SourceLocalMap[$key] -and (Test-Path $SourceLocalMap[$key])) {
            Write-Host "Merging $key (from local backup)..."
            Copy-Item -Path "$($SourceLocalMap[$key])\*" -Destination $Dest -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # B. Restore from the *OneDrive* backup
        if ($SourceOneDriveMap[$key] -and (Test-Path $SourceOneDriveMap[$key])) {
            Write-Host "Merging $key (from OneDrive backup)..."
            Copy-Item -Path "$($SourceOneDriveMap[$key])\*" -Destination $Dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # --- 4. Restore "Other" OneDrive Files ---
    Write-Host "Restoring other OneDrive files..."
    # Only run this if we found a OneDrive backup AND a OneDrive destination
    if ($SourceOneDriveBackup -and $OneDriveFolder) {
        $DestOneDriveRoot = $OneDriveFolder.FullName
        
        Write-Host "Copying extra files to $DestOneDriveRoot..."
        Get-ChildItem -Path $SourceOneDriveBackup.FullName -Exclude @("Desktop", "Documents", "Pictures") | ForEach-Object {
            Write-Host "Copying $($_.Name) to OneDrive root..."
            Copy-Item -Path $_.FullName -Destination $DestOneDriveRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    # --- 5. Restore AppData ---
    Write-Host "Restoring AppData..."
    $NewProfile = $UserProfile
    
    $SourceSignatures = "$SourceBackupPath\AppData_Signatures"
    if (Test-Path $SourceSignatures) {
        Copy-Item -Path "$SourceSignatures\*" -Destination "$NewProfile\AppData\Roaming\Microsoft\Signatures" -Recurse -Force -ErrorAction SilentlyContinue
    }
    $SourceChrome = "$SourceBackupPath\AppData_Chrome"
    if (Test-Path $SourceChrome) {
        Copy-Item -Path $SourceChrome -Destination "$NewProfile\AppData\Local\Google\Chrome\User Data" -Recurse -Force -ErrorAction SilentlyContinue
    }
    $SourceEdge = "$SourceBackupPath\AppData_Edge"
    if (Test-Path $SourceEdge) {
        Copy-Item -Path $SourceEdge -Destination "$NewProfile\AppData\Local\Microsoft\Edge\User Data" -Recurse -Force -ErrorAction SilentlyContinue
    }
    $SourceSticky = "$SourceBackupPath\AppData_StickyNotes\plum.sqlite"
    $DestStickyFolder = "$NewProfile\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState"
    if (Test-Path $SourceSticky) {
        New-Item -ItemType Directory -Path $DestStickyFolder -Force | Out-Null
        Copy-Item -Path $SourceSticky -Destination $DestStickyFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
    $SourceAutocomplete = "$SourceBackupPath\AppData_Autocomplete"
    if (Test-Path $SourceAutocomplete) {
        Copy-Item -Path "$SourceAutocomplete\Stream_Autocomplete_*.dat" -Destination "$NewProfile\AppData\Local\Microsoft\Outlook\RoamCache" -Recurse -Force -ErrorAction SilentlyContinue
    }

    # --- 6. Extras (Registry) ---
    $Global:RestoreMessage = "Restore complete! Files and settings have been copied."
    
    if ($RestoreReg) {
        Write-Host "Restoring mapped drives and wallpaper..."
        $SettingsFile = "$SourceBackupPath\Settings.reg"
        if (Test-Path $SettingsFile) {
            Start-Process -FilePath "reg.exe" -ArgumentList "import `"$SettingsFile`"" -Wait -WindowStyle Hidden
            $Global:RestoreMessage += "`n`nMapped drives and wallpaper have been restored."
            $Global:RestoreMessage += "`n(You may need to sign out and back in for all changes to apply.)"
        }
    }
    
    $Global:RestoreMessage += "`n`n**Check the backup folder for logs of old printers, programs, and drives.**"
    Write-Host "Restore complete!"
    return $true # <--- Signal success
}

# --- 3. MAIN SCRIPT BODY ---

# --- ADMIN CHECK ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show("This script MUST be 'Run as Administrator' to restore profile settings. Please right-click the file and 'Run as Administrator'.", "Error: Admin Required", "OK", "Error")
    Exit
}

# --- 4. GUI or SILENT MODE CHECK ---
if ([string]::IsNullOrWhiteSpace($SourceUser) -or [string]::IsNullOrWhiteSpace($BackupRoot)) {
    # --- RUN IN GUI MODE ---
    Add-Type -AssemblyName System.Windows.Forms

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Profile Restore Tool (v20)"
    $form.Size = New-Object System.Drawing.Size(450, 270)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    
    $labelUser = New-Object System.Windows.Forms.Label
    $labelUser.Location = New-Object System.Drawing.Point(20, 25); $labelUser.Size = New-Object System.Drawing.Size(180, 20); $labelUser.Text = "Backed-up Username (e.g., rchamlee):"
    $form.Controls.Add($labelUser)
    $textUser = New-Object System.Windows.Forms.TextBox
    $textUser.Location = New-Object System.Drawing.Point(200, 23); $textUser.Size = New-Object System.Drawing.Size(200, 20)
    $form.Controls.Add($textUser)
    $labelPath = New-Object System.Windows.Forms.Label
    $labelPath.Location = New-Object System.Drawing.Point(20, 70); $labelPath.Size = New-Object System.Drawing.Size(180, 20); $labelPath.Text = "Backup Source Drive/Folder:"
    $form.Controls.Add($labelPath)
    $textPath = New-Object System.Windows.Forms.TextBox
    $textPath.Location = New-Object System.Drawing.Point(20, 95); $textPath.Size = New-Object System.Drawing.Size(290, 20); $textPath.ReadOnly = $true
    $form.Controls.Add($textPath)
    $buttonBrowse = New-Object System.Windows.Forms.Button
    $buttonBrowse.Location = New-Object System.Drawing.Point(320, 93); $buttonBrowse.Size = New-Object System.Drawing.Size(80, 25); $buttonBrowse.Text = "Browse..."
    $form.Controls.Add($buttonBrowse)
    $checkRestoreExtras = New-Object System.Windows.Forms.CheckBox
    $checkRestoreExtras.Location = New-Object System.Drawing.Point(25, 140); $checkRestoreExtras.Size = New-Object System.Drawing.Size(300, 20); $checkRestoreExtras.Text = "Restore Mapped Drives & Wallpaper"
    $form.Controls.Add($checkRestoreExtras)
    $buttonStart = New-Object System.Windows.Forms.Button
    $buttonStart.Location = New-Object System.Drawing.Point(214, 180); $buttonStart.Size = New-Object System.Drawing.Size(100, 30); $buttonStart.Text = "Start Restore"
    $buttonStart.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($buttonStart)
    $buttonCancel = New-Object System.Windows.Forms.Button
    $buttonCancel.Location = New-Object System.Drawing.Point(320, 180); $buttonCancel.Size = New-Object System.Drawing.Size(80, 30); $buttonCancel.Text = "Cancel"
    $buttonCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($buttonCancel)

    # --- GUI Event Handlers ---
    $buttonBrowse.Add_Click({
        $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowser.Description = "Select the PARENT folder (e.g., D:\Bryan2)"
        if ($folderBrowser.ShowDialog($form) -eq "OK") { $textPath.Text = $folderBrowser.SelectedPath }
    })

    $buttonStart.Add_Click({
        if ([string]::IsNullOrWhiteSpace($textUser.Text) -or [string]::IsNullOrWhiteSpace($textPath.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a username AND select a backup location.", "Error", "OK", "Error")
            return
        }
        $guiUser = $textUser.Text
        $guiRoot = $textPath.Text
        $guiRestoreReg = $checkRestoreExtras.Checked
        $form.Text = "Restore in progress... Please wait."
        $form.Enabled = $false
        $form.Refresh()
        [System.Windows.Forms.MessageBox]::Show("Please ensure all browsers (Chrome, Edge) and Outlook are CLOSED before clicking OK.", "Close Applications", "OK", "Warning")
        
        $Success = Start-Restore -User $guiUser -Root $guiRoot -RestoreReg $guiRestoreReg
        
        $form.Enabled = $true
        $form.Text = "Profile Restore Tool (v20)"
        
        if ($Success -ne $false) {
            [System.Windows.Forms.MessageBox]::Show($Global:RestoreMessage, "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            [System.Windows.Forms.MessageBox]::Show("Restore failed. See console for error (e.g., profile not found).", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    
        $form.Close()
    })

    $form.ShowDialog() | Out-Null

} else {
    # --- RUN IN SILENT MODE ---
    Write-Host "--- Silent Mode Restore Started ---"
    Start-Restore -User $SourceUser -Root $BackupRoot -RestoreReg $RestoreSettings
    Write-Host "--- Silent Mode Restore Finished ---"
}