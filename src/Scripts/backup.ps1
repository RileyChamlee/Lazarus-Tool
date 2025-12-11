# --- THIS MUST BE FIRST ---
[CmdletBinding()]
# --- 1. COMMAND-LINE PARAMETERS ---
param(
    [string]$SourceUser = $null,
    [string]$BackupRoot = $null,
    [switch]$LogPrintersAndPrograms,
    [ValidateSet("None", "Backup", "Log")]
    [string]$MappedDriveMode = "None"
)

# --- 2. CORE BACKUP FUNCTION ---
function Start-Backup {
    param(
        [string]$User,
        [string]$Root,
        [bool]$LogExtras,
        [string]$DrivesMode
    )
    
    Write-Host "Starting backup for $User..."
    $SourceProfilePath = "C:\Users\$User"
    $DestinationPath = Join-Path -Path $Root -ChildPath $User

    if (-not (Test-Path -Path $SourceProfilePath)) {
         Write-Host "ERROR: User profile 'C:\Users\$User' not found."
         if ($pscmdlet.MyInvocation.CommandOrigin -eq 'Runspace') { Exit 1 } else { return }
    }
    
    if (-not (Test-Path -Path $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath
    }

    # --- 1. Standard Profile Folders ---
    Write-Host "Backing up standard profile folders (skipping .ost files)..."
    $FoldersToCopy = @(
        "Desktop", "Documents", "Downloads", "Pictures", 
        "Music", "Videos", "Favorites", "Links"
    )
    $OneDriveFolders = Get-ChildItem -Path $SourceProfilePath -Directory -Filter "OneDrive*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    $FoldersToCopy += $OneDriveFolders 

    foreach ($Folder in $FoldersToCopy) {
        $CurrentSource = Join-Path -Path $SourceProfilePath -ChildPath $Folder
        $CurrentDest = Join-Path -Path $DestinationPath -ChildPath $Folder
        
        Write-Host "Attempting to copy $Folder..."
        Copy-Item -Path $CurrentSource -Destination $CurrentDest -Recurse -Force -ErrorAction SilentlyContinue -Exclude *.ost
    }
    
    # --- 2. AppData ---
    Write-Host "Backing up AppData (skipping cache)..."
    
    # Signatures
    $SourceSignatures = "$SourceProfilePath\AppData\Roaming\Microsoft\Signatures"
    $DestSignatures = "$DestinationPath\AppData_Signatures"
    Copy-Item -Path $SourceSignatures -Destination $DestSignatures -Recurse -Force -ErrorAction SilentlyContinue
    
    # Chrome
    $SourceChrome = "$SourceProfilePath\AppData\Local\Google\Chrome\User Data"
    $DestChrome = "$DestinationPath\AppData_Chrome"
    Copy-Item -Path $SourceChrome -Destination $DestChrome -Recurse -Force -ErrorAction SilentlyContinue -Exclude *Cache*
    
    # Edge
    $SourceEdge = "$SourceProfilePath\AppData\Local\Microsoft\Edge\User Data"
    $DestEdge = "$DestinationPath\AppData_Edge"
    Copy-Item -Path $SourceEdge -Destination $DestEdge -Recurse -Force -ErrorAction SilentlyContinue -Exclude *Cache*
    
    # Sticky Notes
    $SourceSticky = "$SourceProfilePath\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
    if (Test-Path $SourceSticky) {
        New-Item -ItemType Directory -Path "$DestinationPath\AppData_StickyNotes" -Force | Out-Null
        Copy-Item -Path $SourceSticky -Destination "$DestinationPath\AppData_StickyNotes" -Recurse -Force -ErrorAction SilentlyContinue
    }
    # Outlook Autocomplete
    $SourceAutocomplete = "$SourceProfilePath\AppData\Local\Microsoft\Outlook\RoamCache"
    if (Test-Path $SourceAutocomplete) {
        Copy-Item -Path $SourceAutocomplete -Destination "$DestinationPath\AppData_Autocomplete" -Filter "Stream_Autocomplete_*.dat" -Recurse -Force -ErrorAction SilentlyContinue
    }

    # --- 3. Extras (Logs & Registry) ---
    if ($LogExtras) {
        Write-Host "Logging printers and programs..."
        $PrinterLogFile = "$DestinationPath\Printers.csv"
        try { Get-Printer | Select-Object Name, DriverName, PortName, Default, Network | Export-Csv -Path $PrinterLogFile -NoTypeInformation } catch {}
        $ProgramLogFile = "$DestinationPath\Programs.csv"
        try { 
            Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv -Path $ProgramLogFile -NoTypeInformation
            Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv -Path $ProgramLogFile -Append -NoTypeInformation
            Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv -Path $ProgramLogFile -Append -NoTypeInformation
        } catch {}
    }

    $SettingsFile = "$DestinationPath\Settings.reg"
    switch ($DrivesMode) {
        "Backup" {
            Write-Host "Backing up mapped drives, wallpaper, and Outlook settings..."
            # Mapped Drives
            Start-Process -FilePath "reg.exe" -ArgumentList "export ""HKEY_CURRENT_USER\Network"" `"$SettingsFile`" /y" -Wait -WindowStyle Hidden
            # Wallpaper
            Start-Process -FilePath "reg.exe" -ArgumentList "export ""HKEY_CURRENT_USER\Control Panel\Desktop"" `"$SettingsFile`" /a" -Wait -WindowStyle Hidden
            
            # --- THIS IS THE NEW LINE ---
            # Outlook Autodiscover Keys
            Start-Process -FilePath "reg.exe" -ArgumentList "export ""HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\AutoDiscover"" `"$SettingsFile`" /a" -Wait -WindowStyle Hidden
        }
        "Log" {
            Write-Host "Logging mapped drives to .csv file..."
            $DrivesLogFile = "$DestinationPath\MappedDrives.csv"
            try { Get-ItemProperty "HKCU:\Network\*" | Select-Object @{N="Drive";E={$_.PSChildName}}, RemotePath | Export-Csv -Path $DrivesLogFile -NoTypeInformation } catch {}
        }
        "None" { Write-Host "Skipping mapped drives." }
    }
    Write-Host "Backup complete for $User!"
}

# --- 3. MAIN SCRIPT BODY ---

# --- ADMIN CHECK ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show("This script MUST be 'Run as Administrator' to access user profile data. Please right-click the file and 'Run as Administrator'.", "Error: Admin Required", "OK", "Error")
    Exit
}

# --- 4. GUI or SILENT MODE CHECK ---
if ([string]::IsNullOrWhiteSpace($SourceUser) -or [string]::IsNullOrWhiteSpace($BackupRoot)) {
    # --- RUN IN GUI MODE ---
    Add-Type -AssemblyName System.Windows.Forms
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Profile Backup Tool (v21)"
    $form.Size = New-Object System.Drawing.Size(450, 360)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $labelUser = New-Object System.Windows.Forms.Label
    $labelUser.Location = New-Object System.Drawing.Point(20, 25); $labelUser.Size = New-Object System.Drawing.Size(180, 20); $labelUser.Text = "Username to back up (e.g., rchamlee):"
    $form.Controls.Add($labelUser)
    $textUser = New-Object System.Windows.Forms.TextBox
    $textUser.Location = New-Object System.Drawing.Point(200, 23); $textUser.Size = New-Object System.Drawing.Size(200, 20)
    $form.Controls.Add($textUser)
    $labelPath = New-Object System.Windows.Forms.Label
    $labelPath.Location = New-Object System.Drawing.Point(20, 70); $labelPath.Size = New-Object System.Drawing.Size(180, 20); $labelPath.Text = "Backup Destination Drive/Folder:"
    $form.Controls.Add($labelPath)
    $textPath = New-Object System.Windows.Forms.TextBox
    $textPath.Location = New-Object System.Drawing.Point(20, 95); $textPath.Size = New-Object System.Drawing.Size(290, 20); $textPath.ReadOnly = $true
    $form.Controls.Add($textPath)
    $buttonBrowse = New-Object System.Windows.Forms.Button
    $buttonBrowse.Location = New-Object System.Drawing.Point(320, 93); $buttonBrowse.Size = New-Object System.Drawing.Size(80, 25); $buttonBrowse.Text = "Browse..."
    $form.Controls.Add($buttonBrowse)
    $labelFreeSpace = New-Object System.Windows.Forms.Label
    $labelFreeSpace.Location = New-Object System.Drawing.Point(20, 125); $labelFreeSpace.Size = New-Object System.Drawing.Size(380, 20); $labelFreeSpace.Text = "Destination Free Space: (Select a path)"; $labelFreeSpace.ForeColor = "Gray"
    $form.Controls.Add($labelFreeSpace)
    $checkLogExtras = New-Object System.Windows.Forms.CheckBox
    $checkLogExtras.Location = New-Object System.Drawing.Point(25, 165); $checkLogExtras.Size = New-Object System.Drawing.Size(350, 20); $checkLogExtras.Text = "Log Printers & Installed Programs"
    $form.Controls.Add($checkLogExtras)
    $labelDrives = New-Object System.Windows.Forms.Label
    $labelDrives.Location = New-Object System.Drawing.Point(20, 205); $labelDrives.Size = New-Object System.Drawing.Size(100, 20); $labelDrives.Text = "Mapped Drives:"
    $form.Controls.Add($labelDrives)
    $comboDrives = New-Object System.Windows.Forms.ComboBox
    $comboDrives.Location = New-Object System.Drawing.Point(130, 203); $comboDrives.Size = New-Object System.Drawing.Size(270, 20); $comboDrives.DropDownStyle = "DropDownList"
    $comboDrives.Items.Add("Do Nothing"); $comboDrives.Items.Add("Back up (.reg file for restore)"); $comboDrives.Items.Add("Log (.csv file only)"); $comboDrives.SelectedIndex = 0
    $form.Controls.Add($comboDrives)
    $buttonStart = New-Object System.Windows.Forms.Button
    $buttonStart.Location = New-Object System.Drawing.Point(214, 255); $buttonStart.Size = New-Object System.Drawing.Siz
    e(100, 30); $buttonStart.Text = "Start Backup"
    $buttonStart.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($buttonStart)
    $buttonCancel = New-Object System.Windows.Forms.Button
    $buttonCancel.Location = New-Object System.Drawing.Point(320, 255); $buttonCancel.Size = New-Object System.Drawing.Size(80, 30); $buttonCancel.Text = "Cancel"
    $buttonCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($buttonCancel)

    # --- GUI Event Handlers ---
    $buttonBrowse.Add_Click({
        $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($folderBrowser.ShowDialog($form) -eq "OK") { 
            $textPath.Text = $folderBrowser.SelectedPath 
            try {
                $volume = Get-Volume -FilePath $folderBrowser.SelectedPath
                $freeSpace = [math]::Round($volume.SizeRemaining / 1GB, 2)
                $labelFreeSpace.Text = "Destination Free Space: $freeSpace GB"
                if ($freeSpace -lt 20) { $labelFreeSpace.ForeColor = "Red" }
                else { $labelFreeSpace.ForeColor = "DarkGreen" }
            } catch {
                $labelFreeSpace.Text = "Destination Free Space: (Could not query)"
                $labelFreeSpace.ForeColor = "Gray"
            }
        }
    })

    $buttonStart.Add_Click({
        if ([string]::IsNullOrWhiteSpace($textUser.Text) -or ([string]::IsNullOrWhiteSpace($textPath.Text) -and $SourceUser -eq $null)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a username AND select a backup destination.", "Error", "OK", "Error")
            return
        }
        $guiUser = $textUser.Text
        $guiRoot = $textPath.Text
        $guiLogExtras = $checkLogExtras.Checked
        $guiDrivesMode = "None"
        switch ($comboDrives.Text) {
            "Back up (.reg file for restore)" { $guiDrivesMode = "Backup" }
            "Log (.csv file only)"           { $guiDrivesMode = "Log" }
        }
        $form.Text = "Backup in progress... Please wait."
        $form.Enabled = $false
        $form.Refresh()
        [System.Windows.Forms.MessageBox]::Show("Please ensure all browsers (Chrome, Edge) and Outlook are CLOSED before clicking OK.", "Close Applications", "OK", "Warning")
        Start-Backup -User $guiUser -Root $guiRoot -LogExtras $guiLogExtras -DrivesMode $guiDrivesMode
        $form.Enabled = $true
        $form.Text = "Profile Backup Tool (v21)"
        [System.Windows.Forms.MessageBox]::Show("Backup complete! Files are saved in $DestinationPath", "Success", "OK", "Information")
        $form.Close()
    })

    $form.ShowDialog() | Out-Null
    
} else {
    # --- RUN IN SILENT MODE ---
    Write-Host "--- Silent Mode Backup Started ---"
    Start-Backup -User $SourceUser -Root $BackupRoot -LogExtras $LogPrintersAndPrograms -DrivesMode $MappedDriveMode
    Write-Host "--- Silent Mode Backup Finished ---"
}