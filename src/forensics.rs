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
            "9. PII Hunter (Scan for SSN/Credit Cards)", // <--- NEW TOOL
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
            8 => pii_hunter(), // <--- NEW CALL
            _ => break,
        }
    }
}

// --- 9. PII HUNTER (COMPLIANCE SCANNER) ---
fn pii_hunter() {
    println!("{}", "\n[*] PII HUNTER (SENSITIVE DATA SCANNER)...".cyan());
    println!("    (Scans text files for SSN: xxx-xx-xxxx and CC: xxxx-xxxx-xxxx-xxxx)");
    
    let path_str: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter directory to scan (e.g., C:\\Users)")
        .interact_text()
        .unwrap();

    let root = Path::new(&path_str);
    if !root.exists() {
        println!("{}", "    [!] Directory not found.".red());
        pause();
        return;
    }

    println!("{}", "    Scanning files... (This may take a while)".yellow());
    let mut pii_hits = Vec::new();
    let ssn_regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
    let cc_regex = Regex::new(r"\b\d{4}-\d{4}-\d{4}-\d{4}\b").unwrap();

    scan_pii_recursive(root, &ssn_regex, &cc_regex, &mut pii_hits);

    if pii_hits.is_empty() {
        println!("{}", "\n[+] No PII found in text files.".green());
    } else {
        println!("\n[!] POTENTIAL PII FOUND:", );
        println!("{}", "----------------------------------------".red());
        let mut report = String::from("PII SCAN REPORT\n");
        
        for (file, pii_type) in pii_hits {
            println!("[{}] {}", pii_type.red(), file);
            report.push_str(&format!("{} found in {}\n", pii_type, file));
        }
        logger::log_data("PII_Scan", &report);
    }
    pause();
}

fn scan_pii_recursive(dir: &Path, ssn_re: &Regex, cc_re: &Regex, hits: &mut Vec<(String, String)>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_pii_recursive(&path, ssn_re, cc_re, hits);
            } else {
                // Only scan text-like extensions to avoid reading massive binaries
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if matches!(ext_str.as_str(), "txt" | "csv" | "log" | "xml" | "json" | "md" | "ini") {
                        if let Ok(file) = File::open(&path) {
                            let reader = BufReader::new(file);
                            for line in reader.lines().flatten() {
                                if ssn_re.is_match(&line) {
                                    hits.push((path.to_string_lossy().to_string(), "SSN".to_string()));
                                    break; // Stop scanning this file if hit found
                                }
                                if cc_re.is_match(&line) {
                                    hits.push((path.to_string_lossy().to_string(), "CreditCard".to_string()));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// --- EXISTING TOOLS ---

fn usb_history_viewer() {
    println!("{}", "\n[*] SCANNING USB ARTIFACTS...".cyan());
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let usb_key = match hklm.open_subkey("SYSTEM\\CurrentControlSet\\Enum\\USBSTOR") {
        Ok(k) => k,
        Err(_) => { println!("{}", "    [!] Access Denied to Registry.".red()); pause(); return; }
    };
    println!("{:<30} | {}", "DEVICE NAME", "SERIAL / ID");
    println!("{}", "---------------------------------------------------------".blue());
    for name in usb_key.enum_keys().map(|x| x.unwrap()) {
        let clean = name.replace("Disk&Ven_", "").replace("&Prod_", " ");
        println!("{:<30} | {}", clean.green(), "Found in Registry");
    }
    pause();
}

fn bsod_analyzer() {
    println!("{}", "\n[*] ANALYZING SYSTEM CRASHES (BSOD)...".cyan());
    let ps_cmd_bugcheck = "Get-WinEvent -FilterHashtable @{LogName='System'; EventID=1001} -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Out-String -Width 300";
    let output = Command::new("powershell").args(&["-NoProfile", "-Command", ps_cmd_bugcheck]).output().expect("Failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    if stdout.trim().is_empty() { println!("{}", "\n[+] No recent BSODs found.".green()); } 
    else {
        println!("{}", "\n[!] CRASHES DETECTED:".red().bold());
        let re = Regex::new(r"(0x[0-9a-fA-F]{8})").unwrap();
        for line in stdout.lines() {
            if line.trim().is_empty() || line.contains("TimeCreated") || line.contains("---") { continue; }
            println!("{}", "--------------------------------------------------".dimmed());
            println!("{}", line.trim());
            if let Some(caps) = re.captures(line) {
                println!("    -> BugCheck Code: {}", caps.get(1).unwrap().as_str().red().bold());
            }
        }
    }
    pause();
}

fn large_file_scout() {
    println!("{}", "\n[*] SCANNING FOR LARGE FILES (>500MB)...".cyan());
    let mut large_files: Vec<(u64, String)> = Vec::new();
    let user_profile = std::env::var("USERPROFILE").unwrap_or("C:\\".to_string());
    visit_dirs(Path::new(&user_profile), &mut large_files, 500 * 1024 * 1024);
    large_files.sort_by(|a, b| b.0.cmp(&a.0));

    if large_files.is_empty() { println!("{}", "    [+] No files larger than 500MB found.".green()); } 
    else {
        println!("\n{:<15} {}", "SIZE", "PATH");
        println!("{}", "--------------------------------------------------".yellow());
        for (size, path) in large_files.iter().take(20) {
            println!("{:<10} MB   {}", size / 1024 / 1024, path);
        }
    }
    pause();
}

fn visit_dirs(dir: &Path, list: &mut Vec<(u64, String)>, min_size: u64) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if !path.ends_with("AppData") { visit_dirs(&path, list, min_size); }
            } else if let Ok(meta) = path.metadata() {
                if meta.len() > min_size { list.push((meta.len(), path.to_string_lossy().to_string())); }
            }
        }
    }
}

fn startup_audit() {
    println!("{}", "\n[*] SCANNING STARTUP ITEMS...".cyan());
    let ps_cmd = "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider | Format-List";
    run_ps_output("Startup_Audit", ps_cmd);
}

fn get_oem_key() {
    println!("{}", "\n[*] RETRIEVING OEM PRODUCT KEY...".cyan());
    let output = Command::new("wmic").args(&["path", "softwarelicensingservice", "get", "OA3xOriginalProductKey"]).output().expect("Failed");
    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let key = result.lines().last().unwrap_or("Not Found").trim();
    println!("{}", format!("\nOEM LICENSE KEY: {}", key).green().bold());
    pause();
}

fn export_event_logs() {
    println!("{}", "\n[*] EXPORTING CRITICAL EVENT LOGS...".cyan());
    let ps_cmd = "Get-WinEvent -LogName System -MaxEvents 50 -FilterXPath \"*[System[(Level=1 or Level=2)]]\" | Select-Object TimeCreated, Id, ProviderName, Message | Format-Table -AutoSize -Wrap";
    run_ps_output("Event_Log_Dump", ps_cmd);
}

fn user_audit() {
    println!("{}", "\n[*] AUDITING LOCAL ACCOUNTS...".cyan());
    let ps_cmd = "Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description | Format-Table -AutoSize";
    run_ps_output("User_Audit", ps_cmd);
}

fn dump_system_info() {
    println!("{}", "\n[*] Running 'systeminfo'...".cyan());
    let output = Command::new("systeminfo").output().expect("Failed");
    println!("{}", String::from_utf8_lossy(&output.stdout));
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