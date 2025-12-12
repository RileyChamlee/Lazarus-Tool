use crate::logger;
use colored::*;
use dialoguer::{Select, Input, Confirm, theme::ColorfulTheme};
use std::process::Command;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{Read, Write};
use sysinfo::{System, SystemExt};
use winreg::enums::*;
use winreg::RegKey;
use sha2::{Sha256, Digest}; 

// WINDOWS API IMPORTS
use windows::core::{PWSTR, PCWSTR};
use windows::Win32::System::RestartManager::*;
use windows::Win32::System::Services::*; 
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

pub fn menu() {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "--- SYSTEM REPAIR & CONFIGURATION ---".cyan().bold());

        let choices = &[
            "1. User Profile Backup (Migrate User)",
            "2. User Profile Restore (Migrate User)",
            "3. FSLogix Medic (Unlock User / Drain Mode)",
            "4. Browser Deep Clean (Chrome/Edge/Firefox)",
            "5. Remove Bloatware (Xbox, TikTok, Solitaire)",
            "6. Enable WireGuard for Non-Admins",
            "7. Scan for Hardware Errors (Device Manager)",
            "8. Reset Hosts File",
            "9. Nuke Windows Updates (Fix Stuck Updates)",
            "10. Fix Print Spooler (Deep Clean)",
            "11. Disk Cleanup (Temp & Prefetch)",
            "12. Full System Repair (SFC + DISM + Cleanup)",
            "13. Battery Deep Dive",
            "14. Generate Health Report",
            "15. Fix Broken File Extensions (.exe, .lnk)",
            "16. Rogue Admin Hunter (Scan/Demote Admins)",
            "17. File Locksmith (Unlock/Kill Processes)", 
            "18. Duplicate File Destroyer (Find & Delete)",
            "19. UWP App Surgeon (Fix Calc/Photos/Store)",
            "20. Driver Teleporter (Backup/Restore Drivers)",
            "21. Fix Stuck Reboot Loop (QuickBooks/Updates)",
            "22. Bulk File Unblocker (Fix PDF Previews)",
            "23. Trust Server Zone (Prevent Blocked Files)",
            "24. Hung Service Assassin (Kill Stuck Services)", // <--- NEW TOOL
            "Back",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select Action")
            .default(0)
            .items(&choices[..])
            .interact()
            .unwrap();

        match selection {
            0 => profile_backup_workflow(),
            1 => profile_restore_workflow(),
            2 => fslogix_medic(),
            3 => browser_deep_clean(),
            4 => remove_bloatware(),
            5 => enable_wireguard_non_admin(),
            6 => scan_hardware_errors(),
            7 => reset_hosts_file(),
            8 => nuke_windows_updates(),
            9 => print_spooler_cpr(),
            10 => disk_cleanup(),
            11 => run_sfc(),
            12 => battery_forensics(),
            13 => health_report(),
            14 => fix_file_extensions(),
            15 => rogue_admin_hunter(),
            16 => file_locksmith(),
            17 => duplicate_file_destroyer(),
            18 => uwp_app_surgeon(),
            19 => driver_teleporter(),
            20 => nuke_pending_reboot(),
            21 => bulk_unblocker(),
            22 => trust_server_zone(),
            23 => hung_service_assassin(), // <--- NEW CALL
            _ => break,
        }
    }
}

// --- 24. HUNG SERVICE ASSASSIN ---
fn hung_service_assassin() {
    println!("{}", "\n[*] HUNG SERVICE ASSASSIN...".cyan());
    println!("    (Scanning for services stuck in 'STOP_PENDING' or 'START_PENDING')");

    // Use PowerShell to find stuck services because mapping the full Service API structs 
    // manually in Rust is extremely verbose. PS is efficient here.
    
    let ps_cmd = "Get-Service | Where-Object { $_.Status -eq 'StopPending' -or $_.Status -eq 'StartPending' } | Select-Object Name, DisplayName, Status, Id | Format-Table -AutoSize | Out-String";
    
    let output = Command::new("powershell")
        .args(&["-Command", ps_cmd])
        .output()
        .expect("Failed to query services");

    let result = String::from_utf8_lossy(&output.stdout);

    if result.trim().is_empty() {
        println!("{}", "\n[OK] No hung services found.".green());
    } else {
        println!("{}", "\n[!] HUNG SERVICES DETECTED:".red().bold());
        println!("{}", result);

        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Attempt to Force Kill these processes?")
            .default(false)
            .interact()
            .unwrap() 
        {
            // We parse the output to get PIDs. 
            // Actually, simpler to just run a kill loop in PS for safety.
            let kill_cmd = "Get-Service | Where-Object { $_.Status -eq 'StopPending' } | ForEach-Object { Write-Host 'Killing' $_.Name; Stop-Process -Id $_.Id -Force }";
            let _ = Command::new("powershell").args(&["-Command", kill_cmd]).output();
            println!("{}", "[DONE] Kill command sent.".green());
        }
    }
    pause();
}

// --- EXISTING TOOLS (v3.0.2) ---

fn bulk_unblocker() {
    println!("{}", "\n[*] BULK FILE UNBLOCKER...".cyan());
    let path_str: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Enter folder path (e.g., S:\\Scans)").interact_text().unwrap();
    let path = Path::new(&path_str);
    if !path.exists() { println!("{}", "    [!] Path does not exist.".red()); pause(); return; }
    println!("{}", format!("    Unblocking all files in {}...", path_str).yellow());
    let ps_cmd = format!("Get-ChildItem -Path '{}' -Recurse -File | Unblock-File -Verbose", path_str);
    let output = Command::new("powershell").args(&["-Command", &ps_cmd]).output();
    if output.is_ok() { println!("{}", "[SUCCESS] Files unblocked.".green()); } else { println!("{}", "[FAIL] Error.".red()); }
    pause();
}

fn trust_server_zone() {
    println!("{}", "\n[*] TRUST FILE SERVER (INTRANET ZONE)...".cyan());
    let server: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Enter Server Name/IP").interact_text().unwrap();
    println!("{}", format!("    Adding '{}' to Trusted Zone...", server).yellow());
    let ps_script = format!(r#"
        $Server = "{}"
        $Zone = 1 # Local Intranet
        $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\$Server"
        New-Item -Path $RegPath -Force | Out-Null
        New-ItemProperty -Path $RegPath -Name "file" -Value $Zone -PropertyType DWORD -Force | Out-Null
    "#, server);
    let _ = Command::new("powershell").args(&["-Command", &ps_script]).output();
    println!("{}", "[SUCCESS] Server added.".green());
    pause();
}

fn nuke_pending_reboot() {
    println!("{}", "\n[*] CLEARING PENDING REBOOT FLAGS...".cyan());
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut cleared = false;
    if let Ok(key) = hklm.open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Control\\Session Manager", KEY_ALL_ACCESS) {
        if key.delete_value("PendingFileRenameOperations").is_ok() { println!("{}", "    [+] Removed 'PendingFileRenameOperations'.".green()); cleared = true; }
    }
    if let Ok(key) = hklm.open_subkey_with_flags("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update", KEY_ALL_ACCESS) {
        if key.delete_subkey("RebootRequired").is_ok() { println!("{}", "    [+] Removed 'RebootRequired'.".green()); cleared = true; }
    }
    if let Ok(key) = hklm.open_subkey_with_flags("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing", KEY_ALL_ACCESS) {
        if key.delete_subkey("RebootPending").is_ok() { println!("{}", "    [+] Removed 'CBS RebootPending'.".green()); cleared = true; }
    }
    if cleared { println!("{}", "\n[SUCCESS] Reboot flags cleared.".green().bold()); } else { println!("{}", "\n[OK] No flags found.".green()); }
    pause();
}

fn driver_teleporter() {
    println!("{}", "\n[*] DRIVER TELEPORTER...".cyan());
    let choices = &["Export Drivers (Backup)", "Import Drivers (Restore)", "Back"];
    let sel = Select::with_theme(&ColorfulTheme::default()).with_prompt("Select Mode").items(&choices[..]).interact().unwrap();
    match sel {
        0 => {
            let path: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Export Folder").default("C:\\Lazarus_Drivers".to_string()).interact_text().unwrap();
            let _ = fs::create_dir_all(&path);
            println!("{}", "    Exporting... (Wait)".yellow());
            let _ = Command::new("pnputil").args(&["/export-driver", "*", &path]).status();
            println!("{}", "[DONE]".green());
        },
        1 => {
            let path: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Source Folder").interact_text().unwrap();
            println!("{}", "    Installing...".yellow());
            let _ = Command::new("pnputil").args(&["/add-driver", &format!("{}\\*.inf", path), "/subdirs", "/install"]).status();
            println!("{}", "[DONE]".green());
        },
        _ => return,
    }
    pause();
}

fn file_locksmith() {
    println!("{}", "\n[*] FILE LOCKSMITH (UNLOCKER)...".cyan());
    let path_str: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Enter file path").interact_text().unwrap();
    if !Path::new(&path_str).exists() { println!("{}", "    [!] File not found.".red()); pause(); return; }
    println!("{}", "    Checking handles...".yellow());
    unsafe {
        if let Ok(procs) = get_locking_processes(&path_str) {
            if procs.is_empty() { println!("{}", "    [+] No locks found.".green()); } 
            else {
                for (pid, name) in &procs { println!("    LOCKED BY: {} (PID {})", name.red(), pid); }
                if Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Kill processes?").default(false).interact().unwrap() {
                    for (pid, _) in procs { run_cmd("taskkill", &["/F", "/PID", &pid.to_string()], "Terminating"); }
                }
            }
        }
    }
    pause();
}

unsafe fn get_locking_processes(file_path: &str) -> Result<Vec<(u32, String)>, windows::core::Error> {
    let mut session_handle: u32 = 0;
    let mut session_key: [u16; 64] = [0; 64]; 
    let _ = RmStartSession(&mut session_handle, 0, PWSTR(session_key.as_mut_ptr()));
    let wide_path: Vec<u16> = OsStr::new(file_path).encode_wide().chain(Some(0)).collect();
    let pcwstr = PCWSTR(wide_path.as_ptr());
    let resources = [pcwstr];
    let _ = RmRegisterResources(session_handle, Some(&resources), None, None);
    let mut proc_info: [RM_PROCESS_INFO; 10] = std::mem::zeroed();
    let mut proc_count = 10;
    let mut reason = 0;
    let mut needed = 0;
    let res = RmGetList(session_handle, &mut needed, &mut proc_count, Some(proc_info.as_mut_ptr()), &mut reason);
    let mut results = Vec::new();
    if res == 0 || res == 234 { 
        for i in 0..proc_count as usize {
            let pid = proc_info[i].Process.dwProcessId;
            let name_arr = proc_info[i].strAppName;
            let name_len = name_arr.iter().position(|&c| c == 0).unwrap_or(name_arr.len());
            let name = String::from_utf16_lossy(&name_arr[0..name_len]);
            results.push((pid, name));
        }
    }
    let _ = RmEndSession(session_handle);
    Ok(results)
}

fn duplicate_file_destroyer() {
    println!("{}", "\n[*] DUPLICATE FILE DESTROYER...".cyan());
    let path_str: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Directory").interact_text().unwrap();
    let root = Path::new(&path_str);
    if !root.exists() { println!("{}", "    [!] Not found.".red()); pause(); return; }
    println!("{}", "    Scanning...".yellow());
    let mut files_by_size: std::collections::HashMap<u64, Vec<PathBuf>> = std::collections::HashMap::new();
    scan_for_duplicates(root, &mut files_by_size);
    let mut duplicates = Vec::new();
    for (_, files) in files_by_size {
        if files.len() > 1 {
            let mut hashes: std::collections::HashMap<String, Vec<PathBuf>> = std::collections::HashMap::new();
            for f in files { if let Ok(hash) = calculate_hash(&f) { hashes.entry(hash).or_default().push(f); } }
            for (_, group) in hashes { if group.len() > 1 { duplicates.push(group); } }
        }
    }
    if duplicates.is_empty() { println!("{}", "    [+] No duplicates.".green()); } 
    else {
        println!("\n[!] FOUND DUPLICATES:");
        for group in &duplicates {
            println!("{}", "-------------------".blue());
            for (i, file) in group.iter().enumerate() { println!("  [{}] {:?}", i, file); }
            if Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Delete copies?").default(false).interact().unwrap() {
                for file in group.iter().skip(1) { let _ = fs::remove_file(file); }
                println!("{}", "    Deleted.".red());
            }
        }
    }
    pause();
}

fn scan_for_duplicates(dir: &Path, map: &mut std::collections::HashMap<u64, Vec<PathBuf>>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { scan_for_duplicates(&path, map); } 
            else if let Ok(meta) = path.metadata() { if meta.len() > 0 { map.entry(meta.len()).or_default().push(path); } }
        }
    }
}

fn calculate_hash(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 4096];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn rogue_admin_hunter() {
    println!("{}", "\n[*] SCANNING FOR ROGUE ADMINS...".cyan());
    let ps = "Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name";
    let output = Command::new("powershell").args(&["-Command", ps]).output().expect("Failed");
    let text = String::from_utf8_lossy(&output.stdout);
    println!("{:<30} {:<10}", "USER", "STATUS");
    println!("{}", "--------------------------------".blue());
    for user in text.lines().map(|l| l.trim()).filter(|l| !l.is_empty()) {
        let safe = user.to_lowercase().contains("mhk") || user.contains("Domain Admins") || user == "Administrator";
        if safe { println!("{:<30} {}", user, "[SAFE]".green()); }
        else {
            println!("{:<30} {}", user, "[ROGUE]".red().bold());
            if Confirm::with_theme(&ColorfulTheme::default()).with_prompt(&format!("Demote {}?", user)).default(false).interact().unwrap() {
                let _ = Command::new("net").args(&["localgroup", "administrators", user, "/delete"]).output();
                println!("{}", "    [+] Demoted.".green());
            }
        }
    }
    pause();
}

fn uwp_app_surgeon() {
    println!("{}", "\n[*] UWP APP SURGEON...".cyan());
    let apps = &["Calculator", "Photos", "StickyNotes", "Store", "Back"];
    let sel = Select::with_theme(&ColorfulTheme::default()).with_prompt("App to Repair").items(&apps[..]).interact().unwrap();
    let pkg = match sel {
        0 => "Microsoft.WindowsCalculator",
        1 => "Microsoft.Windows.Photos",
        2 => "Microsoft.MicrosoftStickyNotes",
        3 => "Microsoft.WindowsStore",
        _ => return,
    };
    println!("{}", "    Re-registering...".yellow());
    let ps = format!("Get-AppxPackage -AllUsers *{}* | Foreach {{Add-AppxPackage -DisableDevelopmentMode -Register \"$($_.InstallLocation)\\AppXManifest.xml\"}}", pkg);
    let _ = Command::new("powershell").args(&["-Command", &ps]).output();
    println!("{}", "[DONE]".green());
    pause();
}

// --- STANDARD ---
fn remove_bloatware() {
    if Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Run Debloat?").interact().unwrap() {
        run_embedded_powershell("debloat", include_str!("scripts/debloat.ps1"), Vec::new());
    }
}

fn browser_deep_clean() {
    if Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Run Browser Clean?").interact().unwrap() {
        run_embedded_powershell("browser_clean", include_str!("scripts/browser_clean.ps1"), Vec::new());
    }
}

fn fslogix_medic() {
    let choices = &["Unlock User", "Enable Drain", "Disable Drain", "Restart Services", "Back"];
    let sel = Select::with_theme(&ColorfulTheme::default()).with_prompt("FSLogix Medic").items(&choices[..]).interact().unwrap();
    match sel {
        0 => {
            let user: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Username").interact_text().unwrap();
            run_embedded_powershell("fslogix_release", include_str!("scripts/fslogix_release.ps1"), vec!["-TargetUser".to_string(), user]);
        },
        1 => { run_cmd("change", &["logon", "/drain"], "Enabling Drain"); pause(); },
        2 => { run_cmd("change", &["logon", "/enable"], "Disabling Drain"); pause(); },
        3 => { run_cmd("net", &["stop", "frxsvc"], "Stop"); run_cmd("net", &["start", "frxsvc"], "Start"); pause(); },
        _ => return,
    }
}

fn scan_hardware_errors() { run_embedded_powershell("device_audit", include_str!("scripts/device_audit.ps1"), Vec::new()); }

fn reset_hosts_file() {
    let path = Path::new("C:\\Windows\\System32\\drivers\\etc\\hosts");
    if let Ok(mut f) = File::create(path) { let _ = f.write_all(b"# Reset by Lazarus\r\n127.0.0.1 localhost\r\n"); }
    println!("{}", "    [+] Hosts reset.".green()); pause();
}

fn enable_wireguard_non_admin() {
    let _ = RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey("SOFTWARE\\WireGuard").map(|(k,_)| k.set_value("LimitedOperatorUI", &1u32));
    let ps = r#"$User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; Add-LocalGroupMember -Group 'Network Configuration Operators' -Member $User -ErrorAction SilentlyContinue"#;
    let _ = Command::new("powershell").args(&["-Command", ps]).output();
    println!("{}", "    [+] WireGuard patched.".green()); pause();
}

fn fix_file_extensions() {
    run_cmd("cmd", &["/c", "assoc .exe=exefile"], "Fixing .exe");
    run_cmd("cmd", &["/c", "assoc .lnk=lnkfile"], "Fixing .lnk");
    pause();
}

fn profile_backup_workflow() {
    let user: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Username").interact_text().unwrap();
    let dest: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Destination").interact_text().unwrap();
    let args = vec!["-SourceUser".to_string(), user, "-BackupRoot".to_string(), dest, "-MappedDriveMode".to_string(), "Backup".to_string()];
    run_embedded_powershell("backup", include_str!("scripts/backup.ps1"), args);
}

fn profile_restore_workflow() {
    let user: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Username").interact_text().unwrap();
    let src: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Source").interact_text().unwrap();
    let args = vec!["-SourceUser".to_string(), user, "-BackupRoot".to_string(), src, "-RestoreSettings".to_string()];
    run_embedded_powershell("restore", include_str!("scripts/restore.ps1"), args);
}

fn run_embedded_powershell(name: &str, content: &str, ps_args: Vec<String>) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now();
    let timestamp = start.duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis();
    let temp_path = format!("C:\\Windows\\Temp\\lazarus_{}_{}.ps1", name, timestamp);
    { let mut file = File::create(&temp_path).expect("Failed to create temp script"); file.write_all(content.as_bytes()).expect("Failed to write script"); }
    let mut final_args = vec!["-NoProfile".to_string(), "-ExecutionPolicy".to_string(), "Bypass".to_string(), "-File".to_string(), temp_path.clone()];
    final_args.extend(ps_args);
    let mut child = Command::new("powershell").args(&final_args).spawn().expect("Failed");
    let _ = child.wait();
    let _ = std::fs::remove_file(&temp_path);
    pause();
}

fn print_spooler_cpr() {
    run_cmd("net", &["stop", "spooler"], "Stopping");
    clean_folder("C:\\Windows\\System32\\spool\\PRINTERS");
    run_cmd("net", &["start", "spooler"], "Starting");
    pause();
}

fn nuke_windows_updates() {
    let services = ["wuauserv", "cryptSvc", "bits", "msiserver"];
    for s in services.iter() { run_cmd("net", &["stop", s], "Stopping"); }
    rename_folder("C:\\Windows\\SoftwareDistribution", "C:\\Windows\\SoftwareDistribution.old");
    rename_folder("C:\\Windows\\System32\\catroot2", "C:\\Windows\\System32\\catroot2.old");
    for s in services.iter() { run_cmd("net", &["start", s], "Starting"); }
    pause();
}

fn disk_cleanup() {
    clean_folder("C:\\Windows\\Temp");
    clean_folder("C:\\Windows\\Prefetch");
    println!("{}", "[DONE] Temp files purged.".green()); pause();
}

fn run_sfc() {
    println!("{}", "\n[*] Running SFC...".cyan());
    let _ = Command::new("sfc").arg("/scannow").status();
    println!("{}", "\n[*] Running DISM...".cyan());
    let _ = Command::new("dism").args(&["/Online", "/Cleanup-Image", "/RestoreHealth"]).status();
    println!("{}", "[DONE] Repair complete.".green()); pause();
}

fn battery_forensics() { let _ = Command::new("powercfg").args(&["/batteryreport"]).status(); println!("{}", "Battery report generated.".green()); pause(); }
fn health_report() { let mut sys = System::new_all(); sys.refresh_all(); println!("RAM: {} / {} MB", sys.used_memory()/1024/1024, sys.total_memory()/1024/1024); pause(); }
fn run_cmd(cmd: &str, args: &[&str], desc: &str) { print!("[*] {}... ", desc); let _ = Command::new(cmd).args(args).output(); println!("{}", "DONE".green()); }
fn rename_folder(original: &str, new_name: &str) { if Path::new(original).exists() { let _ = fs::rename(original, new_name); } }
fn clean_folder(path_str: &str) { if let Ok(entries) = fs::read_dir(path_str) { for entry in entries { if let Ok(entry) = entry { if entry.path().is_dir() { let _ = fs::remove_dir_all(entry.path()); } else { let _ = fs::remove_file(entry.path()); } } } } }
fn pause() { println!("\nPress Enter to continue..."); let _ = std::io::stdin().read_line(&mut String::new()); }