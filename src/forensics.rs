use crate::logger;
use colored::*;
use dialoguer::{Select, Input, theme::ColorfulTheme};
use std::process::Command;
use std::fs::{self, File};
use std::io::{Write, BufReader, BufRead};
use std::path::Path;
use winreg::enums::*;
use winreg::RegKey;
use regex::Regex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn menu() {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "--- FORENSICS & ANALYSIS ---".cyan().bold());

        let choices = &[
            "1. BSOD Analyzer Pro (Crash Logs)",
            "2. USB History Viewer (Registry Audit)",
            "3. Large File Scout (>500MB)",
            "4. Audit Startup Items",
            "5. Get OEM Product Key",
            "6. Export Recent System Errors",
            "7. User Audit (Local Accounts)",
            "8. Dump Full System Info",
            "9. PII Hunter (Scan for SSN/Credit Cards)",
            "10. ACL Sentinel (Audit Permissions)", // <--- NEW TOOL
            "Back",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select Action")
            .default(0)
            .items(&choices[..])
            .interact()
            .unwrap();

        match selection {
            0 => bsod_analyzer(),
            1 => usb_history_viewer(),
            2 => large_file_scout(),
            3 => startup_audit(),
            4 => get_oem_key(),
            5 => export_event_logs(),
            6 => user_audit(),
            7 => dump_system_info(),
            8 => pii_hunter(),
            9 => acl_sentinel(), // <--- NEW CALL
            _ => break,
        }
    }
}

// --- 10. ACL SENTINEL ---
fn acl_sentinel() {
    println!("{}", "\n[*] ACL SENTINEL (PERMISSION AUDIT)...".cyan());
    println!("    (Scanning for 'Everyone' or 'Users' with WRITE access)");
    
    let path_str: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter directory to audit")
        .interact_text()
        .unwrap();

    let root = Path::new(&path_str);
    if !root.exists() {
        println!("{}", "    [!] Directory not found.".red());
        pause();
        return;
    }

    println!("{}", "    Scanning ACLs... (This uses icacls, please wait)".yellow());
    
    // We use a PowerShell wrapper to efficiently get ACLs recursively and filter bad ones
    let ps_cmd = format!(r#"
        Get-ChildItem -Path '{}' -Recurse -Directory -ErrorAction SilentlyContinue | 
        ForEach-Object {{ 
            $Acl = Get-Acl -Path $_.FullName; 
            foreach ($Access in $Acl.Access) {{ 
                if (($Access.IdentityReference -match 'Everyone' -or $Access.IdentityReference -match 'Users') -and 
                    ($Access.FileSystemRights -match 'FullControl' -or $Access.FileSystemRights -match 'Write')) {{ 
                    Write-Output "$($_.FullName) -> $($Access.IdentityReference) has $($Access.FileSystemRights)" 
                }} 
            }} 
        }}
    "#, path_str);

    let output = Command::new("powershell")
        .args(&["-Command", &ps_cmd])
        .output();

    match output {
        Ok(o) => {
            let result = String::from_utf8_lossy(&o.stdout);
            if result.trim().is_empty() {
                println!("{}", "\n[OK] No loose permissions found.".green());
            } else {
                println!("{}", "\n[!] RISKY PERMISSIONS FOUND:".red().bold());
                println!("{}", result);
                logger::log_data("ACL_Audit", &result);
                println!("{}", "\n[+] Report saved to Lazarus_Reports.".green());
            }
        },
        Err(_) => println!("{}", "[!] Scan failed.".red()),
    }
    pause();
}

// --- EXISTING TOOLS (v3.0.1) ---

fn pii_hunter() {
    println!("{}", "\n[*] PII HUNTER...".cyan());
    let path_str: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Directory").interact_text().unwrap();
    let root = Path::new(&path_str);
    if !root.exists() { println!("{}", "    [!] Not found.".red()); pause(); return; }
    
    println!("{}", "    Scanning files...".yellow());
    let mut hits = Vec::new();
    let ssn_re = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
    let cc_re = Regex::new(r"\b\d{4}-\d{4}-\d{4}-\d{4}\b").unwrap();
    scan_pii_recursive(root, &ssn_re, &cc_re, &mut hits);

    if hits.is_empty() { println!("{}", "    [+] No PII found.".green()); } 
    else {
        println!("{}", "\n[!] PII FOUND:".red());
        let mut report = String::new();
        for (f, t) in hits { 
            println!("[{}] {}", t.red(), f); 
            report.push_str(&format!("{} in {}\n", t, f)); 
        }
        logger::log_data("PII_Scan", &report);
    }
    pause();
}

fn scan_pii_recursive(dir: &Path, ssn: &Regex, cc: &Regex, hits: &mut Vec<(String, String)>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { scan_pii_recursive(&path, ssn, cc, hits); } 
            else if let Some(ext) = path.extension() {
                if matches!(ext.to_string_lossy().to_lowercase().as_str(), "txt"|"csv"|"log"|"xml"|"json") {
                    if let Ok(f) = File::open(&path) {
                        for line in BufReader::new(f).lines().flatten() {
                            if ssn.is_match(&line) { hits.push((path.to_string_lossy().to_string(), "SSN".to_string())); break; }
                            if cc.is_match(&line) { hits.push((path.to_string_lossy().to_string(), "CC".to_string())); break; }
                        }
                    }
                }
            }
        }
    }
}

fn usb_history_viewer() {
    println!("{}", "\n[*] SCANNING USB ARTIFACTS...".cyan());
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let usb_key = match hklm.open_subkey("SYSTEM\\CurrentControlSet\\Enum\\USBSTOR") {
        Ok(k) => k,
        Err(_) => { println!("{}", "    [!] Access Denied.".red()); pause(); return; }
    };
    println!("{:<30} | {}", "DEVICE", "STATUS");
    println!("{}", "----------------------------------------".blue());
    for name in usb_key.enum_keys().map(|x| x.unwrap()) {
        let clean = name.replace("Disk&Ven_", "").replace("&Prod_", " ");
        println!("{:<30} | {}", clean.green(), "Found");
    }
    pause();
}

fn bsod_analyzer() {
    println!("{}", "\n[*] ANALYZING CRASHES...".cyan());
    let ps = "Get-WinEvent -FilterHashtable @{LogName='System'; EventID=1001} -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Out-String -Width 300";
    let output = Command::new("powershell").args(&["-Command", ps]).output().expect("Failed");
    let text = String::from_utf8_lossy(&output.stdout);
    if text.trim().is_empty() { println!("{}", "    [+] No recent crashes.".green()); } 
    else {
        println!("{}", "\n[!] CRASHES DETECTED:".red());
        let re = Regex::new(r"(0x[0-9a-fA-F]{8})").unwrap();
        for line in text.lines() {
            if line.trim().is_empty() || line.contains("TimeCreated") { continue; }
            if let Some(caps) = re.captures(line) { println!("    -> Code: {}", caps.get(1).unwrap().as_str().red().bold()); }
        }
    }
    pause();
}

fn large_file_scout() {
    println!("{}", "\n[*] SCANNING LARGE FILES (>500MB)...".cyan());
    let mut files = Vec::new();
    let profile = std::env::var("USERPROFILE").unwrap_or("C:\\".to_string());
    visit_dirs(Path::new(&profile), &mut files);
    files.sort_by(|a, b| b.0.cmp(&a.0));
    if files.is_empty() { println!("{}", "    [+] None found.".green()); } 
    else {
        println!("{:<10} {}", "SIZE", "PATH");
        for (s, p) in files.iter().take(20) { println!("{:<10} MB   {}", s/1024/1024, p); }
    }
    pause();
}

fn visit_dirs(dir: &Path, list: &mut Vec<(u64, String)>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { if !path.ends_with("AppData") { visit_dirs(&path, list); } } 
            else if let Ok(m) = path.metadata() { if m.len() > 524288000 { list.push((m.len(), path.to_string_lossy().to_string())); } }
        }
    }
}

fn startup_audit() {
    println!("{}", "\n[*] AUDITING STARTUP...".cyan());
    let ps = "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider | Format-List";
    run_ps_output("Startup", ps);
}

fn get_oem_key() {
    println!("{}", "\n[*] GETTING OEM KEY...".cyan());
    let output = Command::new("wmic").args(&["path", "softwarelicensingservice", "get", "OA3xOriginalProductKey"]).output().expect("Failed");
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    pause();
}

fn export_event_logs() {
    println!("{}", "\n[*] EXPORTING LOGS...".cyan());
    let ps = "Get-WinEvent -LogName System -MaxEvents 50 -FilterXPath \"*[System[(Level=1 or Level=2)]]\" | Select-Object TimeCreated, Id, ProviderName, Message | Format-Table -AutoSize -Wrap";
    run_ps_output("System_Logs", ps);
}

fn user_audit() {
    println!("{}", "\n[*] AUDITING USERS...".cyan());
    let ps = "Get-LocalUser | Select-Object Name, Enabled, LastLogon";
    run_ps_output("User_Audit", ps);
}

fn dump_system_info() {
    println!("{}", "\n[*] DUMPING SYSTEM INFO...".cyan());
    let output = Command::new("systeminfo").output().expect("Failed");
    logger::log_data("System_Info", &String::from_utf8_lossy(&output.stdout));
    println!("{}", "    [+] Saved.".green());
    pause();
}

fn run_ps_output(name: &str, cmd: &str) {
    let output = Command::new("powershell").args(&["-Command", cmd]).output().expect("Failed");
    let res = String::from_utf8_lossy(&output.stdout);
    println!("{}", res);
    logger::log_data(name, &res);
    pause();
}

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
}