use crate::logger;
use colored::*;
use dialoguer::{Select, Input, Confirm, theme::ColorfulTheme};
use std::process::Command;
use std::path::Path;
use std::fs::{self, File};
use std::io::Write;
use sysinfo::{System, SystemExt, DiskExt};
use winreg::enums::*;
use winreg::RegKey;

pub fn menu() {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "--- SYSTEM REPAIR & CONFIGURATION ---".cyan().bold());

        let choices = &[
            "1. User Profile Backup (Migrate User)",
            "2. User Profile Restore (Migrate User)",
            "3. FSLogix Medic (Unlock User / Drain Mode)",
            "4. Sage 300 Excel Fix (Trusted Locations)",
            "5. Enable WireGuard for Non-Admins",
            "6. Scan for Hardware Errors (Device Manager)",
            "7. Remove Bloatware (Xbox, TikTok, Solitaire)",
            "8. Reset Hosts File",
            "9. Nuke Windows Updates (Fix Stuck Updates)",
            "10. Fix Print Spooler (Deep Clean)",
            "11. Disk Cleanup (Temp & Prefetch)",
            "12. Run SFC /Scannow",
            "13. Battery Deep Dive",
            "14. Generate Health Report",
            "15. Fix Broken File Extensions (.exe, .lnk)",
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
            3 => sage_excel_fix(),
            4 => enable_wireguard_non_admin(),
            5 => scan_hardware_errors(),
            6 => remove_bloatware(),
            7 => reset_hosts_file(),
            8 => nuke_windows_updates(),
            9 => print_spooler_cpr(),
            10 => disk_cleanup(),
            11 => run_sfc(),
            12 => battery_forensics(),
            13 => health_report(),
            14 => fix_file_extensions(),
            _ => break,
        }
    }
}

// --- FSLOGIX MEDIC ---

fn fslogix_medic() {
    println!("{}", "\n--- FSLOGIX MEDIC ---".red().bold());
    let choices = &[
        "1. Unlock Specific User (Kill Zombie Processes)", // The surgical fix
        "2. Emergency: Enable DRAIN MODE (Stop new logins)",
        "3. Recovery: Disable DRAIN MODE (Allow logins)",
        "4. Service CPR: Restart FSLogix Services",
        "Back"
    ];
    
    let sel = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select Action")
        .default(0)
        .items(&choices[..])
        .interact()
        .unwrap();

    match sel {
        0 => fslogix_unlock_user(),
        1 => set_drain_mode(true),
        2 => set_drain_mode(false),
        3 => restart_fslogix(),
        _ => return,
    }
}

fn fslogix_unlock_user() {
    println!("{}", "\n[*] UNLOCKING STUCK USER PROFILE...".cyan());
    
    let user: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter the Username to unlock (e.g., jsmith)")
        .interact_text()
        .unwrap();

    let script = include_str!("scripts/fslogix_release.ps1");
    // Pass the username as an argument to the script
    run_embedded_powershell("fslogix_release", script, vec!["-TargetUser".to_string(), user]);
}

fn set_drain_mode(enable: bool) {
    let arg = if enable { "/drain" } else { "/enable" };
    let desc = if enable { "ENABLING Drain Mode" } else { "DISABLING Drain Mode" };
    
    println!("\n[*] {}...", desc);
    run_cmd("change", &["logon", arg], desc);
    
    if enable {
        println!("{}", "\n[!] Server is now in DRAIN MODE. No new users can connect.".yellow());
    } else {
        println!("{}", "\n[+] Server is now accepting connections.".green());
    }
    pause();
}

fn restart_fslogix() {
    println!("{}", "\n[*] RESTARTING FSLOGIX SERVICES...".cyan());
    run_cmd("net", &["stop", "frxsvc"], "Stopping FSLogix Service");
    run_cmd("net", &["stop", "frxccds"], "Stopping FSLogix Cloud Cache");
    
    run_cmd("net", &["start", "frxsvc"], "Starting FSLogix Service");
    run_cmd("net", &["start", "frxccds"], "Starting FSLogix Cloud Cache");
    
    println!("{}", "\n[DONE] Services cycled.".green());
    pause();
}

// --- SAGE FIX ---

fn sage_excel_fix() {
    println!("{}", "\n[*] APPLYING SAGE 300 EXCEL FIXES...".cyan());
    let script = include_str!("scripts/sage_fix.ps1");
    run_embedded_powershell("sage_fix", script, Vec::new());
}

// --- EXISTING FEATURES ---

fn scan_hardware_errors() {
    println!("{}", "\n[*] SCANNING PNP DEVICES FOR ERRORS...".cyan());
    let script = include_str!("scripts/device_audit.ps1");
    run_embedded_powershell("device_audit", script, Vec::new());
}

fn remove_bloatware() {
    println!("{}", "\n[*] STARTING BLOATWARE ASSASSIN...".cyan());
    let script = include_str!("scripts/debloat.ps1");
    run_embedded_powershell("debloat", script, Vec::new());
}

fn reset_hosts_file() {
    println!("{}", "\n[*] RESETTING HOSTS FILE...".cyan());
    let hosts_path = Path::new("C:\\Windows\\System32\\drivers\\etc\\hosts");
    let backup_path = Path::new("C:\\Windows\\System32\\drivers\\etc\\hosts.bak");
    if hosts_path.exists() { let _ = fs::copy(hosts_path, backup_path); }
    let default_hosts = "# Default Windows Hosts File\r\n127.0.0.1 localhost\r\n::1 localhost\r\n";
    if let Ok(mut f) = File::create(hosts_path) { let _ = f.write_all(default_hosts.as_bytes()); }
    println!("{}", "    [+] Hosts file reset.".green());
    pause();
}

fn enable_wireguard_non_admin() {
    println!("{}", "\n[*] ENABLING WIREGUARD FOR NON-ADMINS...".cyan());
    println!("    Setting Registry Key (LimitedOperatorUI)...");
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey("SOFTWARE\\WireGuard").expect("Failed to open/create WireGuard registry key");
    match key.set_value("LimitedOperatorUI", &1u32) {
        Ok(_) => println!("{}", "    [+] Registry updated successfully.".green()),
        Err(e) => println!("    {} {}", "[!] Registry Error:".red(), e),
    }

    println!("\n    Adding current user to 'Network Configuration Operators'...");
    let ps_cmd = r#"
    $User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    try { Add-LocalGroupMember -Group 'Network Configuration Operators' -Member $User -ErrorAction Stop; Write-Output "SUCCESS: $User added." } 
    catch { if ($_.Exception.Message -like "*already a member*") { Write-Output "SKIP: $User is already a member." } else { Write-Error $_.Exception.Message } }
    "#;
    let output = Command::new("powershell").args(&["-Command", ps_cmd]).output().expect("Failed to execute PowerShell");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() { println!("    [+] {}", stdout.green()); }
    println!("{}", "\n[IMPORTANT] The user must LOG OFF and LOG BACK IN for these changes to work.".yellow().bold());
    pause();
}

fn fix_file_extensions() {
    println!("{}", "\n[*] RESETTING FILE ASSOCIATIONS...".cyan());
    run_cmd("cmd", &["/c", "assoc", ".exe=exefile"], "Resetting .exe");
    run_cmd("cmd", &["/c", "ftype", "exefile=\"%1\" %*"], "Resetting exefile handler");
    run_cmd("cmd", &["/c", "assoc", ".lnk=lnkfile"], "Resetting .lnk");
    println!("{}", "\n[DONE] Common file extensions reset.".green());
    pause();
}

fn profile_backup_workflow() {
    println!("{}", "\n--- PROFILE BACKUP WIZARD ---".cyan());
    let user: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Enter the Username to back up").interact_text().unwrap();
    let path: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Enter Backup Destination").interact_text().unwrap();
    let log_extras = Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Log Installed Printers & Programs?").default(true).interact().unwrap();
    let modes = &["None (Skip Drives)", "Backup (Save Registry Keys)", "Log (Save CSV List)"];
    let mode_sel = Select::with_theme(&ColorfulTheme::default()).with_prompt("Mapped Drive Strategy").default(1).items(&modes[..]).interact().unwrap();
    let drive_mode = match mode_sel { 1 => "Backup", 2 => "Log", _ => "None" };

    let mut args = vec![
        "-SourceUser".to_string(), user.clone(),
        "-BackupRoot".to_string(), path.clone(),
        "-MappedDriveMode".to_string(), drive_mode.to_string(),
    ];
    if log_extras { args.push("-LogPrintersAndPrograms".to_string()); }
    let script = include_str!("scripts/backup.ps1");
    run_embedded_powershell("backup", script, args);
}

fn profile_restore_workflow() {
    println!("{}", "\n--- PROFILE RESTORE WIZARD ---".cyan());
    let user: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Enter the Username to Restore").interact_text().unwrap();
    let path: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Enter Backup Source Folder").interact_text().unwrap();
    let restore_settings = Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Restore Mapped Drives & Wallpaper?").default(true).interact().unwrap();
    let mut args = vec![ "-SourceUser".to_string(), user, "-BackupRoot".to_string(), path ];
    if restore_settings { args.push("-RestoreSettings".to_string()); }
    let script = include_str!("scripts/restore.ps1");
    run_embedded_powershell("restore", script, args);
}

// --- HELPER FOR EMBEDDED SCRIPTS ---
fn run_embedded_powershell(name: &str, content: &str, ps_args: Vec<String>) {
    println!("{}", format!("\n[*] Preparing {} engine...", name).yellow());
    let temp_path = format!("C:\\Windows\\Temp\\lazarus_{}.ps1", name);

    // Write file and IMMEDIATELY close it to release lock
    {
        let mut file = File::create(&temp_path).expect("Failed to create temp script");
        file.write_all(content.as_bytes()).expect("Failed to write script");
    }

    let mut final_args = vec![
        "-NoProfile".to_string(),
        "-ExecutionPolicy".to_string(),
        "Bypass".to_string(),
        "-File".to_string(),
        temp_path.clone()
    ];
    final_args.extend(ps_args);

    println!("{}", "[*] Launching PowerShell Process...".cyan());
    let mut child = Command::new("powershell")
        .args(&final_args)
        .spawn()
        .expect("Failed to launch PowerShell");

    let _ = child.wait();
    
    // Cleanup
    let _ = std::fs::remove_file(&temp_path);
    println!("{}", "\n[DONE] Operation complete.".green());
    pause();
}

// --- BASIC SYSTEM COMMANDS ---

fn print_spooler_cpr() {
    println!("{}", "\n[*] INITIATING PRINT SPOOLER CPR...".cyan());
    run_cmd("net", &["stop", "spooler"], "Stopping Print Spooler");
    let spool_dir = "C:\\Windows\\System32\\spool\\PRINTERS";
    if let Ok(entries) = fs::read_dir(spool_dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                if entry.path().is_file() { let _ = fs::remove_file(entry.path()); }
            }
        }
    }
    run_cmd("net", &["start", "spooler"], "Restarting Print Spooler");
    println!("{}", "\n[DONE] Print system reset.".green());
    pause();
}

fn nuke_windows_updates() {
    println!("{}", "\n[!] INITIATING WINDOWS UPDATE RESET...".red().bold());
    let services = ["wuauserv", "cryptSvc", "bits", "msiserver"];
    for service in services.iter() { run_cmd("net", &["stop", service], &format!("Stopping {}", service)); }
    rename_folder("C:\\Windows\\SoftwareDistribution", "C:\\Windows\\SoftwareDistribution.old");
    rename_folder("C:\\Windows\\System32\\catroot2", "C:\\Windows\\System32\\catroot2.old");
    for service in services.iter() { run_cmd("net", &["start", service], &format!("Starting {}", service)); }
    println!("{}", "\n[SUCCESS] Windows Update cache cleared.".green().bold());
    pause();
}

fn disk_cleanup() {
    println!("{}", "\n[*] RUNNING DISK CLEANUP...".cyan());
    clean_folder("C:\\Windows\\Temp");
    clean_folder("C:\\Windows\\Prefetch");
    let _ = Command::new("cmd").args(&["/C", "del /q/f/s %TEMP%\\*"]).output();
    println!("{}", "[DONE] Temporary files purged.".green());
    pause();
}

fn run_sfc() {
    println!("{}", "\n[*] Starting System File Checker (Wait 10-15m)...".cyan());
    let mut child = Command::new("sfc").arg("/scannow").spawn().expect("Failed");
    let _ = child.wait();
    println!("{}", "\n[DONE] SFC Scan Complete.".green());
    pause();
}

fn battery_forensics() {
    println!("{}", "\n[*] ANALYZING BATTERY CHEMISTRY...".cyan());
    let temp_report = std::env::temp_dir().join("battery_report.xml");
    let _ = Command::new("powercfg").args(&["/batteryreport", "/xml", "/output", temp_report.to_str().unwrap()]).output();
    if let Ok(content) = fs::read_to_string(&temp_report) {
        let design = extract_val(&content, "DesignCapacity");
        let full = extract_val(&content, "FullChargeCapacity");
        let report = format!("BATTERY FORENSICS\n=================\nDesign: {} mWh\nCurrent Max: {} mWh\nHealth: {}%", design, full, calculate_health(&design, &full));
        println!("{}", report.green());
        logger::log_data("Battery_Deep_Dive", &report);
    } else { println!("{}", "[!] Could not generate report.".red()); }
    let _ = fs::remove_file(temp_report);
    pause();
}

fn health_report() {
    println!("{}", "\n[*] Gathering System Metrics...".cyan());
    let mut sys = System::new_all();
    sys.refresh_all();
    let total_ram = sys.total_memory() / 1024 / 1024;
    let used_ram = sys.used_memory() / 1024 / 1024;
    let mut disk_info = String::new();
    for disk in sys.disks() { disk_info.push_str(&format!("Drive: {:?} | Total: {} GB | Free: {} GB\n", disk.name(), disk.total_space() / 1024 / 1024 / 1024, disk.available_space() / 1024 / 1024 / 1024)); }
    let report = format!("SYSTEM HEALTH\n-------------\nHostname: {:?}\nOS: {:?}\nRAM: {} / {} MB\n\nDISKS:\n{}", sys.host_name().unwrap_or_default(), sys.os_version().unwrap_or_default(), used_ram, total_ram, disk_info);
    logger::log_data("Health_Report", &report);
    println!("{}", report);
    pause();
}

fn run_cmd(cmd: &str, args: &[&str], desc: &str) {
    print!("[*] {}... ", desc);
    use std::io::{self, Write};
    io::stdout().flush().unwrap();
    let _ = Command::new(cmd).args(args).output();
    println!("{}", "DONE".green());
}

fn rename_folder(original: &str, new_name: &str) {
    if Path::new(original).exists() {
        print!("[*] Renaming {}... ", original);
        let _ = fs::rename(original, new_name);
        println!("{}", "OK".green());
    }
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

fn extract_val(xml: &str, tag: &str) -> String {
    let search = format!("<{}>", tag);
    if let Some(start) = xml.find(&search) {
        if let Some(end) = xml[start..].find(&format!("</{}>", tag)) { return xml[start + search.len() .. start + end].to_string(); }
    }
    "0".to_string()
}

fn calculate_health(design: &str, full: &str) -> String {
    let d: f32 = design.trim().parse().unwrap_or(1.0);
    let f: f32 = full.trim().parse().unwrap_or(0.0);
    if d == 0.0 { return "Unknown".to_string(); }
    format!("{:.2}", (f / d) * 100.0)
}

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
}