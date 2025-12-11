use crate::logger;
use colored::*;
use dialoguer::{Select, theme::ColorfulTheme};
use std::process::Command;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub fn menu() {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "--- FORENSICS & INFO ---".cyan().bold());

        let choices = &[
            "1. Crash Detective (Analyze BSODs & App Crashes)",
            "2. Large File Scout (Find Top Space Hogs)", // NEW
            "3. Harvest WiFi Keys",
            "4. Audit Startup Items",
            "5. Get OEM Product Key",
            "6. Export Recent System Errors",
            "7. USB History",
            "8. User Audit",
            "9. Dump Full System Info",
            "Back",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select Action")
            .default(0)
            .items(&choices[..])
            .interact()
            .unwrap();

        match selection {
            0 => analyze_crashes(),
            1 => large_file_scout(),
            2 => harvest_wifi(),
            3 => startup_audit(),
            4 => get_oem_key(),
            5 => export_event_logs(),
            6 => usb_history(),
            7 => user_audit(),
            8 => dump_system_info(),
            _ => break,
        }
    }
}

// --- NEW FEATURE ---

fn large_file_scout() {
    println!("{}", "\n[*] SCANNING FOR LARGE FILES (>500MB)...".cyan());
    println!("    (Scanning current user profile recursively. This may take a minute.)");

    // We use a simple vector to hold results: (Size, Path)
    let mut large_files: Vec<(u64, String)> = Vec::new();
    let user_profile = std::env::var("USERPROFILE").unwrap_or("C:\\".to_string());
    let min_size = 500 * 1024 * 1024; // 500 MB

    // Start recursion
    visit_dirs(Path::new(&user_profile), &mut large_files, min_size);

    // Sort descending by size
    large_files.sort_by(|a, b| b.0.cmp(&a.0));

    if large_files.is_empty() {
        println!("{}", "    [+] No files larger than 500MB found.".green());
    } else {
        println!("\n{:<15} {}", "SIZE", "PATH");
        println!("{}", "--------------------------------------------------".yellow());
        let mut log_content = String::from("LARGE FILES REPORT:\n");
        
        // Take top 20
        for (size, path) in large_files.iter().take(20) {
            let size_mb = size / 1024 / 1024;
            let line = format!("{:<10} MB   {}", size_mb, path);
            println!("{}", line);
            log_content.push_str(&format!("{}\n", line));
        }
        logger::log_data("Large_Files", &log_content);
    }
    pause();
}

// Recursive helper (ignores errors/Access Denied)
fn visit_dirs(dir: &Path, list: &mut Vec<(u64, String)>, min_size: u64) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    // Don't recurse into AppData (too slow/locked) or hidden system folders
                    if !path.ends_with("AppData") && !path.ends_with("Application Data") {
                        visit_dirs(&path, list, min_size);
                    }
                } else {
                    if let Ok(metadata) = entry.metadata() {
                        let len = metadata.len();
                        if len > min_size {
                            list.push((len, path.to_string_lossy().to_string()));
                        }
                    }
                }
            }
        }
    }
}

// --- EXISTING FEATURES ---

fn analyze_crashes() {
    println!("{}", "\n[*] RUNNING CRASH DETECTIVE...".cyan());
    let script = include_str!("scripts/crash_audit.ps1");
    run_ps_script("crash_audit", script);
}

fn startup_audit() {
    println!("{}", "\n[*] SCANNING STARTUP ITEMS...".cyan());
    let ps_cmd = r#"
    Write-Output "--- REGISTRY RUN KEYS (HKCU) ---"
    Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run | Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider | Format-List
    Write-Output "--- REGISTRY RUN KEYS (HKLM) ---"
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run | Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider | Format-List
    Write-Output "--- STARTUP FOLDER ITEMS ---"
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" | Select-Object Name, FullName
    "#;
    run_ps_output("Startup_Audit", ps_cmd);
}

fn get_oem_key() {
    println!("{}", "\n[*] RETRIEVING OEM PRODUCT KEY...".cyan());
    let output = Command::new("wmic").args(&["path", "softwarelicensingservice", "get", "OA3xOriginalProductKey"]).output().expect("Failed");
    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let key = result.lines().last().unwrap_or("Not Found").trim();
    if key.is_empty() { println!("{}", "[!] No OEM Key found.".yellow()); } 
    else { 
        println!("{}", format!("\nOEM LICENSE KEY: {}", key).green().bold());
        logger::log_data("OEM_Key", &format!("Product Key: {}", key));
    }
    pause();
}

fn export_event_logs() {
    println!("{}", "\n[*] EXPORTING CRITICAL EVENT LOGS...".cyan());
    let ps_cmd = "Get-WinEvent -LogName System -MaxEvents 50 -FilterXPath \"*[System[(Level=1 or Level=2)]]\" | Select-Object TimeCreated, Id, ProviderName, Message | Format-Table -AutoSize -Wrap";
    run_ps_output("Event_Log_Dump", ps_cmd);
}

fn harvest_wifi() {
    println!("{}", "\n[*] HUNTING FOR WIFI KEYS...".cyan());
    let output = Command::new("netsh").args(&["wlan", "show", "profiles"]).output().expect("Failed");
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut profiles = Vec::new();
    for line in output_str.lines() {
        if line.contains("All User Profile") {
            if let Some(ssid) = line.split(':').nth(1) { profiles.push(ssid.trim().to_string()); }
        }
    }
    if profiles.is_empty() { println!("{}", "[!] No profiles found.".red()); pause(); return; }
    
    let mut full_report = String::new();
    full_report.push_str("WIFI HARVEST REPORT\n===================\n");
    for ssid in profiles {
        print!("    Extracting: {} ... ", ssid);
        let key_output = Command::new("netsh").args(&["wlan", "show", "profile", &format!("name={}", ssid), "key=clear"]).output();
        if let Ok(o) = key_output {
            let text = String::from_utf8_lossy(&o.stdout);
            let password = text.lines().find(|l| l.contains("Key Content")).map(|l| l.split(':').nth(1).unwrap_or(" (None)").trim()).unwrap_or("(Open/None)");
            println!("{}", "OK".green());
            full_report.push_str(&format!("SSID: {}\nPASS: {}\n\n", ssid, password));
        } else { println!("{}", "FAILED".red()); }
    }
    logger::log_data("Wifi_Keys", &full_report);
    pause();
}

fn usb_history() {
    println!("{}", "\n[*] SCANNING USB ARTIFACTS...".cyan());
    let ps_cmd = r#"Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' | Select-Object FriendlyName, @{N='ConnectedTime';E={$_.LastWriteTime}} | Sort-Object ConnectedTime -Descending | Format-Table -AutoSize"#;
    run_ps_output("USB_History", ps_cmd);
}

fn user_audit() {
    println!("{}", "\n[*] AUDITING LOCAL ACCOUNTS...".cyan());
    let ps_cmd = "Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description | Format-Table -AutoSize; Write-Output \"`n--- ADMINS ---\"; Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, PrincipalSource";
    run_ps_output("User_Audit", ps_cmd);
}

fn dump_system_info() {
    println!("{}", "\n[*] Running 'systeminfo'...".cyan());
    let output = Command::new("systeminfo").output().expect("Failed");
    let result = String::from_utf8_lossy(&output.stdout).to_string();
    logger::log_data("System_Audit", &result);
    pause();
}

// --- HELPER FUNCTIONS ---

fn run_ps_script(name: &str, content: &str) {
    let temp_path = format!("C:\\Windows\\Temp\\lazarus_{}.ps1", name);
    let mut file = File::create(&temp_path).expect("Failed to create temp script");
    file.write_all(content.as_bytes()).expect("Failed to write script");

    let mut child = Command::new("powershell")
        .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", &temp_path])
        .spawn()
        .expect("Failed to launch PowerShell");
    let _ = child.wait();
    let _ = std::fs::remove_file(&temp_path);
    pause();
}

fn run_ps_output(log_name: &str, cmd: &str) {
    let output = Command::new("powershell").args(&["-Command", cmd]).output().expect("Failed");
    let result = String::from_utf8_lossy(&output.stdout).to_string();
    println!("{}", result);
    logger::log_data(log_name, &result);
    pause();
}

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
}