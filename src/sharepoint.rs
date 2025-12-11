use crate::logger;
use colored::*;
use dialoguer::{Input, Confirm};
use std::fs;
use std::path::Path;
use std::time::Instant;

pub fn menu() {
    print!("\x1B[2J\x1B[1;1H");
    println!("{}", "--- SHAREPOINT MIGRATION PRE-FLIGHT ---".cyan().bold());

    // 1. Get Source Path
    let path_str: String = Input::new()
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
    let auto_rename = Confirm::new()
        .with_prompt("Auto-rename illegal characters? (Replaces # % & with _)")
        .default(false)
        .interact()
        .unwrap();

    println!("{}", "\n[*] STARTING SCAN... (This may take time for large drives)".yellow());
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

                // 1. Check Path Length (> 400 is the hard limit, usually 256 is safe zone)
                if path_str.len() > 390 {
                    issues.push(("LENGTH".to_string(), path_str.clone()));
                }

                // 2. Check Illegal Chars
                // SharePoint blocks: " * : < > ? / \ | # %
                // Windows blocks most, but # and % are valid in Windows but BAD in SharePoint
                if let Some(filename) = path.file_name() {
                    let fname = filename.to_string_lossy();
                    if fname.contains('#') || fname.contains('%') {
                        if rename {
                            // Rename Logic
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