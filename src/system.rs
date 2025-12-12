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
            "4. Browser Deep Clean (Chrome/Edge/Firefox)",
            "5. Remove Bloatware (Xbox, TikTok, Solitaire)", // <--- RESTORED
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
            4 => remove_bloatware(), // <--- RESTORED FUNCTION
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
            _ => break,
        }
    }
}

// --- RESTORED: REMOVE BLOATWARE ---
fn remove_bloatware() {
    println!("{}", "\n[*] STARTING BLOATWARE ASSASSIN...".cyan());
    println!("    (Removing: Xbox, Solitaire, BingNews, Zune, etc.)");
    
    // We add a confirmation because this modifies the OS
    if !Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Proceed with Debloat?").interact().unwrap() {
        return;
    }

    let script = include_str!("scripts/debloat.ps1");
    run_embedded_powershell("debloat", script, Vec::new());
}

// --- BROWSER CLEAN ---
fn browser_deep_clean() {
    println!("{}", "\n[*] STARTING BROWSER DEEP CLEAN...".cyan());
    println!("    (This will force close Chrome, Edge, and Firefox)");
    
    if !Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Proceed?").interact().unwrap() {
        return;
    }

    let script = include_str!("scripts/browser_clean.ps1");
    run_embedded_powershell("browser_clean", script, Vec::new());
}

// --- FSLOGIX MEDIC ---
fn fslogix_medic() {
    println!("{}", "\n--- FSLOGIX MEDIC ---".red().bold());
    let choices = &[
        "1. Unlock Specific User (Kill Zombie Processes)",
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
    let user: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Enter Username").interact_text().unwrap();
    let script = include_str!("scripts/fslogix_release.ps1");
    run_embedded_powershell("fslogix_release", script, vec!["-TargetUser".to_string(), user]);
}

fn set_drain_mode(enable: bool) {
    let arg = if enable { "/drain" } else { "/enable" };
    let desc = if enable { "ENABLING Drain Mode" } else { "DISABLING Drain Mode" };
    run_cmd("change", &["logon", arg], desc);
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

// --- EXISTING FEATURES ---
fn scan_hardware_errors() {
    println!("{}", "\n[*] SCANNING PNP DEVICES FOR ERRORS...".cyan());
    let script = include_str!("scripts/device_audit.ps1");
    run_embedded_powershell("device_audit", script, Vec::new());
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
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok((key, _)) = hklm.create_subkey("SOFTWARE\\WireGuard") {
        let _ = key.set_value("LimitedOperatorUI", &1u32);
        println!("{}", "    [+] Registry updated.".green());
    }
    let ps_cmd = r#"$User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; Add-LocalGroupMember -Group 'Network Configuration Operators' -Member $User -ErrorAction SilentlyContinue"#;
    let _ = Command::new("powershell").args(&["-Command", ps_cmd]).output();
    println!("{}", "    [+] User added to Network Ops group.".green());
    pause();
}

fn fix_file_extensions() {
    println!("{}", "\n[*] RESETTING FILE ASSOCIATIONS...".cyan());
    run_cmd("cmd", &["/c", "assoc", ".exe=exefile"], "Resetting .exe");
    run_cmd("cmd", &["/c", "ftype", "exefile=\"%1\" %*"], "Resetting exefile");
    run_cmd("cmd", &["/c", "assoc", ".lnk=lnkfile"], "Resetting .lnk");
    println!("{}", "\n[DONE] Common file extensions reset.".green());
    pause();
}

fn profile_backup_workflow() {
    println!("{}", "\n--- PROFILE BACKUP WIZARD ---".cyan());
    let user: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Username to back up").interact_text().unwrap();
    let path: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Backup Destination").interact_text().unwrap();
    let args = vec!["-SourceUser".to_string(), user, "-BackupRoot".to_string(), path, "-MappedDriveMode".to_string(), "Backup".to_string()];
    let script = include_str!("scripts/backup.ps1");
    run_embedded_powershell("backup", script, args);
}

fn profile_restore_workflow() {
    println!("{}", "\n--- PROFILE RESTORE WIZARD ---".cyan());
    let user: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Username to Restore").interact_text().unwrap();
    let path: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Backup Source Folder").interact_text().unwrap();
    let args = vec!["-SourceUser".to_string(), user, "-BackupRoot".to_string(), path, "-RestoreSettings".to_string()];
    let script = include_str!("scripts/restore.ps1");
    run_embedded_powershell("restore", script, args);
}

// --- HELPER FOR EMBEDDED SCRIPTS ---
fn run_embedded_powershell(name: &str, content: &str, ps_args: Vec<String>) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now();
    let since_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let timestamp = since_epoch.as_millis();
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
    println!("{}", "\n[*] INITIATING PRINT SPOOLER CPR...".cyan());
    run_cmd("net", &["stop", "spooler"], "Stopping");
    clean_folder("C:\\Windows\\System32\\spool\\PRINTERS");
    run_cmd("net", &["start", "spooler"], "Starting");
    pause();
}

fn nuke_windows_updates() {
    println!("{}", "\n[!] INITIATING WINDOWS UPDATE RESET...".red().bold());
    let services = ["wuauserv", "cryptSvc", "bits", "msiserver"];
    for s in services.iter() { run_cmd("net", &["stop", s], "Stopping Service"); }
    rename_folder("C:\\Windows\\SoftwareDistribution", "C:\\Windows\\SoftwareDistribution.old");
    rename_folder("C:\\Windows\\System32\\catroot2", "C:\\Windows\\System32\\catroot2.old");
    for s in services.iter() { run_cmd("net", &["start", s], "Starting Service"); }
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