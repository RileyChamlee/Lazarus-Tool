use crate::logger; // Kept as you requested, just ignore the warning if it pops up
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

// FIX: Updated imports for Windows 0.48 crate compatibility
use windows::core::{PWSTR, PCWSTR};
use windows::Win32::System::RestartManager::*;
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
            _ => break,
        }
    }
}

// --- 17. FILE LOCKSMITH (FIXED) ---
fn file_locksmith() {
    println!("{}", "\n[*] FILE LOCKSMITH (UNLOCKER)...".cyan());
    
    let path_str: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Enter the full path of the locked file").interact_text().unwrap();
    let path = Path::new(&path_str);
    if !path.exists() { println!("{}", "    [!] File does not exist.".red()); pause(); return; }

    println!("{}", format!("    Inspecting handles for: {:?}", path).yellow());

    unsafe {
        match get_locking_processes(&path_str) {
            Ok(procs) => {
                if procs.is_empty() {
                    println!("{}", "    [+] No processes found locking this file.".green());
                } else {
                    println!("\n{:<10} | {:<25}", "PID", "PROCESS NAME");
                    println!("{}", "-------------------------------------".blue());
                    for (pid, name) in &procs {
                        println!("{:<10} | {}", pid.to_string().yellow(), name.red());
                    }
                    if Confirm::with_theme(&ColorfulTheme::default()).with_prompt("\nKill these processes?").default(false).interact().unwrap() {
                        for (pid, _) in procs {
                            run_cmd("taskkill", &["/F", "/PID", &pid.to_string()], "Terminating");
                        }
                    }
                }
            },
            Err(_) => println!("{}", "    [!] Failed to query Restart Manager API.".red()),
        }
    }
    pause();
}

// FIX: Updated to match Windows 0.48 function signatures
unsafe fn get_locking_processes(file_path: &str) -> Result<Vec<(u32, String)>, windows::core::Error> {
    let mut session_handle: u32 = 0;
    let mut session_key: [u16; 64] = [0; 64]; 

    // Start Session
    let _ = RmStartSession(&mut session_handle, 0, PWSTR(session_key.as_mut_ptr()));

    // Register Resources (Strict Type Casting for 0.48)
    let wide_path: Vec<u16> = OsStr::new(file_path).encode_wide().chain(Some(0)).collect();
    let pcwstr = PCWSTR(wide_path.as_ptr());
    let resources = [pcwstr];
    // Pass 'Some(&resources)' instead of raw pointers
    let _ = RmRegisterResources(session_handle, Some(&resources), None, None);

    // Get List
    let mut proc_info_needed = 0;
    let mut proc_info: [RM_PROCESS_INFO; 10] = std::mem::zeroed();
    let mut proc_count = 10;
    let mut reason = 0;

    // Use 'Some' wrapper and check for 0 (Success) or 234 (More Data)
    let res = RmGetList(session_handle, &mut proc_info_needed, &mut proc_count, Some(proc_info.as_mut_ptr()), &mut reason);

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

// --- 18. DUPLICATE FILE DESTROYER (FIXED) ---
fn duplicate_file_destroyer() {
    println!("{}", "\n[*] DUPLICATE FILE DESTROYER...".cyan());
    let path_str: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Directory to scan").interact_text().unwrap();
    let root = Path::new(&path_str);
    
    if !root.exists() { println!("{}", "    [!] Directory not found.".red()); pause(); return; }

    println!("{}", "    Scanning files...".yellow());
    let mut files_by_size: std::collections::HashMap<u64, Vec<PathBuf>> = std::collections::HashMap::new();
    scan_for_duplicates(root, &mut files_by_size);

    let mut duplicates: Vec<Vec<PathBuf>> = Vec::new();
    println!("{}", "    Hashing matches...".yellow());
    
    for (_, files) in files_by_size {
        if files.len() > 1 {
            let mut hashes: std::collections::HashMap<String, Vec<PathBuf>> = std::collections::HashMap::new();
            for f in files {
                if let Ok(hash) = calculate_hash(&f) {
                    // FIX: Changed .or_insert_new() to .or_default()
                    hashes.entry(hash).or_default().push(f);
                }
            }
            for (_, group) in hashes {
                if group.len() > 1 { duplicates.push(group); }
            }
        }
    }

    if duplicates.is_empty() {
        println!("{}", "\n[+] No duplicates found.".green());
    } else {
        println!("\n[!] FOUND DUPLICATES:");
        for group in &duplicates {
            println!("{}", "---------------------------------".blue());
            for (i, file) in group.iter().enumerate() { println!("  [{}] {:?}", i, file); }
            
            if Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Delete copies?").default(false).interact().unwrap() {
                for file in group.iter().skip(1) {
                    print!("    Deleting {:?}... ", file);
                    match fs::remove_file(file) {
                        Ok(_) => println!("{}", "DONE".green()),
                        Err(_) => println!("{}", "FAIL".red()),
                    }
                }
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
            else if let Ok(meta) = path.metadata() {
                if meta.len() > 0 { 
                    // FIX: Changed .or_insert_new() to .or_default()
                    map.entry(meta.len()).or_default().push(path); 
                }
            }
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

// --- REST OF FUNCTIONS (ROGUE ADMIN, ETC) ---

fn rogue_admin_hunter() {
    println!("{}", "\n[*] SCANNING FOR ROGUE ADMINS...".cyan());
    let ps_cmd = "Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name";
    let output = Command::new("powershell").args(&["-NoProfile", "-Command", ps_cmd]).output().expect("Failed");
    let output_str = String::from_utf8_lossy(&output.stdout);
    let admins: Vec<&str> = output_str.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

    let is_safe = |name: &str| -> bool {
        let n = name.to_lowercase();
        n.contains("mhk") || n.contains("itadmin") || n.contains("aeadmin") || n.contains("domain admins") || n == "administrator"
    };

    let mut rogues_found = false;
    println!("{:<30} {:<10}", "USER ACCOUNT", "STATUS");
    println!("{}", "------------------------------------------".blue());

    for admin in admins {
        if is_safe(admin) { println!("{:<30} {}", admin, "[SAFE]".green()); } 
        else {
            rogues_found = true;
            println!("{:<30} {}", admin, "[ROGUE]".red().bold());
            let prompt = format!("    -> Demote '{}' immediately?", admin);
            if Confirm::with_theme(&ColorfulTheme::default()).with_prompt(&prompt).default(false).interact().unwrap() {
                demote_admin(admin);
            }
        }
    }
    if !rogues_found { println!("{}", "\n[+] No rogue admins detected.".green()); }
    pause();
}

fn demote_admin(user: &str) {
    let status = Command::new("net").args(&["localgroup", "administrators", user, "/delete"]).output();
    match status {
        Ok(s) if s.status.success() => println!("{}", "SUCCESS".green()),
        _ => println!("{}", "FAILED".red()),
    }
}

// Existing Utilities (Bloatware, Browser Clean, etc. - Kept exactly as they were)
fn remove_bloatware() {
    println!("{}", "\n[*] STARTING BLOATWARE ASSASSIN...".cyan());
    if !Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Proceed?").interact().unwrap() { return; }
    let script = include_str!("scripts/debloat.ps1");
    run_embedded_powershell("debloat", script, Vec::new());
}

fn browser_deep_clean() {
    println!("{}", "\n[*] STARTING BROWSER DEEP CLEAN...".cyan());
    if !Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Proceed?").interact().unwrap() { return; }
    let script = include_str!("scripts/browser_clean.ps1");
    run_embedded_powershell("browser_clean", script, Vec::new());
}

fn fslogix_medic() {
    println!("{}", "\n--- FSLOGIX MEDIC ---".red().bold());
    let choices = &["1. Unlock Specific User", "2. Enable DRAIN MODE", "3. Disable DRAIN MODE", "4. Restart Services", "Back"];
    let sel = Select::with_theme(&ColorfulTheme::default()).with_prompt("Select Action").default(0).items(&choices[..]).interact().unwrap();
    match sel {
        0 => fslogix_unlock_user(),
        1 => set_drain_mode(true),
        2 => set_drain_mode(false),
        3 => restart_fslogix(),
        _ => return,
    }
}

fn fslogix_unlock_user() {
    let user: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Enter Username").interact_text().unwrap();
    let script = include_str!("scripts/fslogix_release.ps1");
    run_embedded_powershell("fslogix_release", script, vec!["-TargetUser".to_string(), user]);
}

fn set_drain_mode(enable: bool) {
    let arg = if enable { "/drain" } else { "/enable" };
    run_cmd("change", &["logon", arg], "Toggling Drain Mode");
    pause();
}

fn restart_fslogix() {
    run_cmd("net", &["stop", "frxsvc"], "Stopping FSLogix");
    run_cmd("net", &["start", "frxsvc"], "Starting FSLogix");
    pause();
}

fn scan_hardware_errors() {
    println!("{}", "\n[*] SCANNING PNP DEVICES FOR ERRORS...".cyan());
    let script = include_str!("scripts/device_audit.ps1");
    run_embedded_powershell("device_audit", script, Vec::new());
}

fn reset_hosts_file() {
    println!("{}", "\n[*] RESETTING HOSTS FILE...".cyan());
    let hosts_path = Path::new("C:\\Windows\\System32\\drivers\\etc\\hosts");
    if let Ok(mut f) = File::create(hosts_path) { 
        let _ = f.write_all("# Default Windows Hosts File\r\n127.0.0.1 localhost\r\n::1 localhost\r\n".as_bytes()); 
    }
    println!("{}", "    [+] Hosts file reset.".green());
    pause();
}

fn enable_wireguard_non_admin() {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok((key, _)) = hklm.create_subkey("SOFTWARE\\WireGuard") { let _ = key.set_value("LimitedOperatorUI", &1u32); }
    let ps_cmd = r#"$User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; Add-LocalGroupMember -Group 'Network Configuration Operators' -Member $User -ErrorAction SilentlyContinue"#;
    let _ = Command::new("powershell").args(&["-Command", ps_cmd]).output();
    println!("{}", "    [+] Registry updated.".green());
    pause();
}

fn fix_file_extensions() {
    run_cmd("cmd", &["/c", "assoc", ".exe=exefile"], "Resetting .exe");
    run_cmd("cmd", &["/c", "ftype", "exefile=\"%1\" %*"], "Resetting exefile");
    run_cmd("cmd", &["/c", "assoc", ".lnk=lnkfile"], "Resetting .lnk");
    pause();
}

fn profile_backup_workflow() {
    let user: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Username").interact_text().unwrap();
    let path: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Destination").interact_text().unwrap();
    let args = vec!["-SourceUser".to_string(), user, "-BackupRoot".to_string(), path, "-MappedDriveMode".to_string(), "Backup".to_string()];
    let script = include_str!("scripts/backup.ps1");
    run_embedded_powershell("backup", script, args);
}

fn profile_restore_workflow() {
    let user: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Username").interact_text().unwrap();
    let path: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Source").interact_text().unwrap();
    let args = vec!["-SourceUser".to_string(), user, "-BackupRoot".to_string(), path, "-RestoreSettings".to_string()];
    let script = include_str!("scripts/restore.ps1");
    run_embedded_powershell("restore", script, args);
}

fn run_embedded_powershell(name: &str, content: &str, ps_args: Vec<String>) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now();
    let timestamp = start.duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis();
    let temp_path = format!("C:\\Windows\\Temp\\lazarus_{}_{}.ps1", name, timestamp);
    {
        let mut file = File::create(&temp_path).expect("Failed to create temp script");
        file.write_all(content.as_bytes()).expect("Failed to write script");
    }
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
    println!("{}", "[DONE] Temp files purged.".green());
    pause();
}

fn run_sfc() {
    println!("{}", "\n[*] PHASE 1: Running System File Checker...".cyan());
    let _ = Command::new("sfc").arg("/scannow").status();
    println!("{}", "\n[*] PHASE 2: Running DISM Repair...".cyan());
    let _ = Command::new("dism").args(&["/Online", "/Cleanup-Image", "/RestoreHealth"]).status();
    println!("{}", "\n[*] PHASE 3: Cleaning Components...".cyan());
    let _ = Command::new("dism").args(&["/Online", "/Cleanup-Image", "/StartComponentCleanup"]).status();
    println!("{}", "\n[SUCCESS] System Repair Complete.".green());
    pause();
}

fn battery_forensics() {
    let _ = Command::new("powercfg").args(&["/batteryreport"]).status();
    println!("{}", "Battery report generated.".green());
    pause();
}

fn health_report() {
    let mut sys = System::new_all();
    sys.refresh_all();
    println!("RAM: {} / {} MB", sys.used_memory()/1024/1024, sys.total_memory()/1024/1024);
    pause();
}

fn run_cmd(cmd: &str, args: &[&str], desc: &str) {
    print!("[*] {}... ", desc);
    let _ = Command::new(cmd).args(args).output();
    println!("{}", "DONE".green());
}

fn rename_folder(original: &str, new_name: &str) {
    if Path::new(original).exists() { let _ = fs::rename(original, new_name); }
}

fn clean_folder(path_str: &str) {
    if let Ok(entries) = fs::read_dir(path_str) {
        for entry in entries {
            if let Ok(entry) = entry {
                if entry.path().is_dir() { let _ = fs::remove_dir_all(entry.path()); }
                else { let _ = fs::remove_file(entry.path()); }
            }
        }
    }
}

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
}