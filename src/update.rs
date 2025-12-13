use colored::*;
use std::fs;
use std::io::Write;
use std::env;
use std::process::Command;

// --- CONFIGURATION ---
const GITHUB_USER: &str = "RileyChamlee"; 
const GITHUB_REPO: &str = "Lazarus-Tool"; 

pub fn check_for_updates(current_version: &str) {
    println!("{}", "\n[*] CONTACTING UPDATE SERVER...".cyan());

    // 1. Get Latest Release Info from GitHub API
    let url = format!("https://api.github.com/repos/{}/{}/releases/latest", GITHUB_USER, GITHUB_REPO);
    
    // We set a User-Agent because GitHub blocks requests without one
    let resp = match ureq::get(&url).set("User-Agent", "Lazarus-Updater").call() {
        Ok(r) => r,
        Err(_) => {
            println!("{}", "    [!] Connection Failed. (Are you online?)".red());
            pause();
            return;
        }
    };

    // Use serde_json to read the stream directly.
    let json: serde_json::Value = match serde_json::from_reader(resp.into_reader()) {
        Ok(j) => j,
        Err(_) => {
            println!("{}", "    [!] Failed to parse update data.".red());
            pause();
            return;
        }
    };

    // 2. Parse Version Tag (e.g., "v1.0.5")
    // FIX: Using unwrap_or to prevent crashing if GitHub API changes
    let remote_tag = json["tag_name"].as_str().unwrap_or("v0.0.0");
    let remote_ver = remote_tag.trim_start_matches('v');

    println!("    Current Version: {}", current_version.yellow());
    println!("    Latest Version:  {}", remote_ver.yellow());

    if remote_ver == current_version {
        println!("{}", "\n[+] You are already running the latest version.".green());
        pause();
        return;
    }

    // 3. Prompt for Auto-Update
    println!("{}", format!("\n[!] UPDATE AVAILABLE: v{}", remote_ver).green().bold());
    println!("    (This will download the new version and restart)");

    let confirm = dialoguer::Confirm::new()
        .with_prompt("Install Update Now?")
        .default(true)
        .interact()
        .unwrap();

    if !confirm { return; }

    // 4. Find the Asset URL
    if let Some(assets) = json["assets"].as_array() {
        for asset in assets {
            if asset["name"] == "lazarus.exe" {
                if let Some(download_url) = asset["browser_download_url"].as_str() {
                    perform_update(download_url);
                    return;
                }
            }
        }
    }
    
    println!("{}", "    [!] Error: 'lazarus.exe' not found in the latest release.".red());
    pause();
}

fn perform_update(url: &str) {
    println!("{}", "\n[*] DOWNLOADING NEW VERSION...".yellow());

    // 1. Download File
    let resp = ureq::get(url).call().expect("Download failed");
    let mut bytes = Vec::new();
    resp.into_reader().read_to_end(&mut bytes).expect("Failed to read bytes");

    // 2. Determine Paths
    let current_exe = env::current_exe().expect("Failed to get current path");
    let current_dir = current_exe.parent().unwrap();
    
    let new_exe = current_dir.join("lazarus_new.exe");
    let old_exe = current_dir.join("lazarus_old.exe");

    // 3. Save New EXE to Disk
    let mut file = fs::File::create(&new_exe).expect("Failed to create new file");
    file.write_all(&bytes).expect("Failed to write new file");
    println!("    [+] Download complete ({} bytes).", bytes.len());

    // 4. The Swap Trick
    println!("    [*] Applying update...");

    // Clean up any previous "old" file
    if old_exe.exists() {
        let _ = fs::remove_file(&old_exe);
    }

    // RENAME: Current -> Old
    if let Err(e) = fs::rename(&current_exe, &old_exe) {
        println!("    [!] Failed to rename current file: {}", e);
        println!("    (Try closing Lazarus and running as Admin)");
        pause();
        return;
    }

    // RENAME: New -> Current
    if let Err(e) = fs::rename(&new_exe, &current_exe) {
        println!("    [!] Failed to swap new file: {}", e);
        // Emergency Rollback
        let _ = fs::rename(&old_exe, &current_exe);
        pause();
        return;
    }

    println!("{}", "\n[SUCCESS] Update Complete!".green().bold());
    println!("{}", "Lazarus will now restart...".cyan());
    
    // 5. Auto-Restart
    Command::new(&current_exe)
        .spawn()
        .expect("Failed to restart");
        
    std::process::exit(0);
}

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
}