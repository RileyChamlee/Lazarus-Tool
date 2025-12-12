use crate::logger;
use colored::*;
use dialoguer::{Input, Confirm, Select, theme::ColorfulTheme};
use std::fs;
use std::path::Path;
use std::time::Instant;
use std::process::Command;

pub fn menu() {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "--- SHAREPOINT & ONEDRIVE TOOLS ---".cyan().bold());

        let choices = &[
            "1. SharePoint Pre-Flight Scan (Bad Chars/Length)", // Restored
            "2. OneDrive Nuclear Reset (Fix Sync Issues)",      // New
            "3. Clear OneDrive Credentials",                    // New
            "Back",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select Action")
            .default(0)
            .items(&choices[..])
            .interact()
            .unwrap();

        match selection {
            0 => preflight_scan(),
            1 => onedrive_nuclear_reset(),
            2 => clear_creds(),
            _ => break,
        }
    }
}

// --- NEW TOOLS ---

fn onedrive_nuclear_reset() {
    println!("{}", "\n[!] ONEDRIVE NUCLEAR RESET [!]".red().bold());
    println!("    This will Kill OneDrive, Wipe Caches, and Force Re-sync.");
    if !Confirm::with_theme(&ColorfulTheme::default()).with_prompt("Proceed?").interact().unwrap() { return; }

    println!("{}", "[*] Killing OneDrive...".yellow());
    let _ = Command::new("taskkill").args(&["/f", "/im", "onedrive.exe"]).output();
    
    let reset_cmd = r#"%localappdata%\Microsoft\OneDrive\onedrive.exe /reset"#;
    println!("{}", "[*] Triggering /reset command...".yellow());
    let _ = Command::new("cmd").args(&["/C", reset_cmd]).output();
    
    println!("{}", "[*] Waiting 15 seconds...".dimmed());
    std::thread::sleep(std::time::Duration::from_secs(15));

    println!("{}", "[*] Restarting OneDrive...".green());
    let start_cmd = r#"%localappdata%\Microsoft\OneDrive\onedrive.exe"#;
    let _ = Command::new("cmd").args(&["/C", start_cmd]).spawn();
    
    println!("{}", "\n[DONE] OneDrive reset. It may take a minute to reappear.".green());
    pause();
}

fn clear_creds() {
    println!("{}", "\n[*] CLEARING CREDENTIAL MANAGER (OneDrive)...".cyan());
    let script = "cmdkey /list | Select-String 'OneDrive' -Context 0,1 | ForEach-Object { cmdkey /delete:($_ -replace 'Target: ','') }";
    let _ = Command::new("powershell").args(&["-Command", script]).output();
    println!("{}", "[DONE] Cached credentials removed.".green());
    pause();
}

// --- RESTORED TOOL ---

fn preflight_scan() {
    println!("{}", "\n[*] SHAREPOINT MIGRATION SCANNER...".cyan());

    // 1. Get Source Path
    let path_str: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter path to scan (e.g., X:\\Data)")
        .interact_text()
        .unwrap();

    let path = Path::new(&path_str);
    if !path.exists() {
        println!("{}", "[!] Path does not exist.".red());
        pause();
        return;
    }

    // 2. Options
    let auto_rename = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Auto-rename illegal characters? (Replaces # % & with _)")
        .default(false)
        .interact()
        .unwrap();

    println!("{}", "\n[*] STARTING SCAN... (This may take time)".yellow());
    let start = Instant::now();

    let mut issues = Vec::new();
    let mut scanned_count = 0;

    // Start recursion
    scan_dir(path, &mut issues, &mut scanned_count, auto_rename);

    let duration = start.elapsed();
    
    // 3. Report
    println!("{}", "\n--- SCAN COMPLETE ---".green().bold());
    println!("Files Scanned: {}", scanned_count);
    println!("Time Elapsed:  {:.2?}", duration);
    println!("Issues Found:  {}", issues.len());

    if !issues.is_empty() {
        println!("{}", "---------------------------------------------------".yellow());
        println!("{:<10} {:<60}", "TYPE", "FILE");
        
        let mut report_content = String::from("TYPE,PATH\n");
        
        for (issue_type, file_path) in issues.iter().take(20) {
            println!("{:<10} {}", issue_type.red(), file_path);
            report_content.push_str(&format!("{},{}\n", issue_type, file_path));
        }
        
        if issues.len() > 20 {
            println!("... (and {} more)", issues.len() - 20);
        }

        // Save full CSV
        logger::log_data("SharePoint_Scan", &report_content);
        println!("{}", "\n[+] Full list saved to Lazarus_Reports folder.".green());
    } else {
        println!("{}", "[+] No SharePoint compatibility issues found!".green());
    }

    pause();
}

fn scan_dir(dir: &Path, issues: &mut Vec<(String, String)>, count: &mut u64, rename: bool) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                let path_str = path.to_string_lossy().to_string();
                *count += 1;

                // 1. Check Path Length
                if path_str.len() > 390 {
                    issues.push(("LENGTH".to_string(), path_str.clone()));
                }

                // 2. Check Illegal Chars
                if let Some(filename) = path.file_name() {
                    let fname = filename.to_string_lossy();
                    if fname.contains('#') || fname.contains('%') {
                        if rename {
                            let new_name = fname.replace("#", "_").replace("%", "_");
                            let new_path = path.with_file_name(&new_name);
                            match fs::rename(&path, &new_path) {
                                Ok(_) => issues.push(("RENAMED".to_string(), format!("{} -> {}", fname, new_name))),
                                Err(_) => issues.push(("RENAME_FAIL".to_string(), path_str.clone())),
                            }
                        } else {
                            issues.push(("CHAR".to_string(), path_str.clone()));
                        }
                    }
                }

                // Recurse
                if path.is_dir() {
                    scan_dir(&path, issues, count, rename);
                }
            }
        }
    }
}

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
}