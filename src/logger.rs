use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use chrono::Local;
use colored::*;

/// Saves text content to a file in the "Lazarus_Reports" folder.
pub fn log_data(filename_prefix: &str, content: &str) {
    
    // 1. Define folder
    let report_dir = Path::new("Lazarus_Reports");
    if !report_dir.exists() {
        if let Err(e) = fs::create_dir(report_dir) {
            println!("{} {}", "[!] Failed to create report dir:".red(), e);
            return;
        }
    }

    // 2. Generate Filename
    let date = Local::now().format("%Y-%m-%d").to_string();
    let filename = format!("{}_{}.txt", filename_prefix, date);
    let file_path = report_dir.join(filename);

    // 3. Prepare Entry
    let time = Local::now().format("%H:%M:%S").to_string();
    let entry = format!("\n[{}] \n{}\n----------------------------------------", time, content);

    // 4. Write to file
    let file_result = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file_path);

    match file_result {
        Ok(mut file) => {
            if let Err(e) = writeln!(file, "{}", entry) {
                eprintln!("{} {}", "[!] Write Error:".red(), e);
            } else {
                println!("{} {:?}", "[+] Log saved to:".green(), file_path);
            }
        },
        Err(e) => {
            eprintln!("{} {}", "[!] Could not open file:".red(), e);
        }
    }
}