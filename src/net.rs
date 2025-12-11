use crate::logger;
use colored::*;
use dialoguer::{Select, Input, theme::ColorfulTheme};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub fn menu() {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "--- NETWORK TOOLS ---".cyan().bold());

        let choices = &[
            "1. Subnet Scanner (Find Active IPs)", // NEW
            "2. Network Nuke (Reset Stack)",
            "3. Connectivity Test (Ping Google/Cloudflare)",
            "4. Save IP Configuration to Log",
            "Back",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select Action")
            .default(0)
            .items(&choices[..])
            .interact()
            .unwrap();

        match selection {
            0 => subnet_scanner(),
            1 => nuke_network(),
            2 => connectivity_test(),
            3 => save_ip_config(),
            _ => break,
        }
    }
}

// --- NEW FEATURE: SUBNET SCANNER ---

fn subnet_scanner() {
    println!("{}", "\n[*] STARTING SUBNET SCANNER...".cyan());

    // 1. Get the Subnet Base (e.g., 192.168.1)
    // We try to guess it from ipconfig, but asking the user is safer/faster for now
    let subnet: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter Subnet Base (e.g., 192.168.1 or 10.0.0)")
        .interact_text()
        .unwrap();

    println!("{}", format!("\n[*] Scanning {}.1 through {}.254 ...", subnet, subnet).yellow());
    println!("    (This takes about 5-10 seconds. Please wait.)");

    // Thread-safe vector to hold results
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = vec![];

    // 2. Launch 254 threads
    // We use standard ping.exe because it's whitelisted by most AVs
    for i in 1..=254 {
        let subnet_clone = subnet.clone();
        let results_clone = Arc::clone(&results);

        let handle = thread::spawn(move || {
            let ip = format!("{}.{}", subnet_clone, i);
            
            // -n 1 = 1 ping
            // -w 200 = 200ms timeout (fast scan)
            let output = Command::new("ping")
                .args(&["-n", "1", "-w", "200", &ip])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // Windows ping returns "TTL=" if it succeeds
                if stdout.contains("TTL=") {
                    // Try to resolve hostname
                    let hostname = resolve_hostname(&ip);
                    
                    let mut data = results_clone.lock().unwrap();
                    data.push((i, ip, hostname));
                }
            }
        });
        handles.push(handle);
    }

    // 3. Wait for all threads to finish
    for handle in handles {
        let _ = handle.join();
    }

    // 4. Sort and Display
    let mut final_results = results.lock().unwrap();
    // Sort numerically by the last octet (i)
    final_results.sort_by(|a, b| a.0.cmp(&b.0));

    println!("\n{:<16} {:<30}", "IP ADDRESS", "HOSTNAME");
    println!("{}", "-----------------------------------------------".green());
    
    let mut log_output = String::from("IP SCAN RESULTS:\n");

    if final_results.is_empty() {
        println!("{}", "No active devices found (Check your subnet?).".red());
    } else {
        for (_, ip, host) in final_results.iter() {
            let line = format!("{:<16} {}", ip, host);
            println!("{}", line);
            log_output.push_str(&format!("{}\n", line));
        }
    }

    // Save to log
    logger::log_data("IP_Scan", &log_output);
    println!("\n[DONE] Scan complete. List saved to logs.");
    pause();
}

fn resolve_hostname(ip: &str) -> String {
    // We use "ping -a" logic or nbtstat. 
    // Simplest built-in way is actually nslookup or just rely on DNS cache.
    // Let's use a quick nslookup
    let output = Command::new("nslookup")
        .arg(ip)
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        // Parse "Name:    Simpsons-PC.domain.local"
        for line in stdout.lines() {
            if line.trim().starts_with("Name:") {
                return line.replace("Name:", "").trim().to_string();
            }
        }
    }
    return "(Unknown)".to_string();
}

// --- EXISTING FEATURES ---

fn nuke_network() {
    println!("{}", "\n[!] INITIATING NETWORK RESET...".yellow());
    run_cmd("ipconfig", &["/flushdns"], "Flushing DNS");
    run_cmd("ipconfig", &["/release"], "Releasing IP");
    run_cmd("ipconfig", &["/renew"], "Renewing IP");
    run_cmd("netsh", &["winsock", "reset"], "Resetting Winsock");
    run_cmd("netsh", &["int", "ip", "reset"], "Resetting TCP/IP Stack");
    println!("{}", "\n[SUCCESS] Network stack reset complete. Reboot recommended.".green().bold());
    pause();
}

fn connectivity_test() {
    println!("{}", "\n[*] TESTING CONNECTIVITY...".cyan());
    print!("    Pinging Google DNS (8.8.8.8)... ");
    let google = Command::new("ping").args(&["8.8.8.8", "-n", "2"]).output().expect("Failed");
    if google.status.success() { println!("{}", "ONLINE".green()); } else { println!("{}", "UNREACHABLE".red()); }

    print!("    Pinging Cloudflare (1.1.1.1)... ");
    let cf = Command::new("ping").args(&["1.1.1.1", "-n", "2"]).output().expect("Failed");
    if cf.status.success() { println!("{}", "ONLINE".green()); } else { println!("{}", "UNREACHABLE".red()); }
    pause();
}

fn save_ip_config() {
    println!("{}", "\n[*] Capturing IP Configuration...".cyan());
    let output = Command::new("ipconfig").arg("/all").output().expect("Failed");
    let result = String::from_utf8_lossy(&output.stdout).to_string();
    logger::log_data("Network_Config", &result);
    pause();
}

fn run_cmd(cmd: &str, args: &[&str], desc: &str) {
    print!("[*] {}... ", desc);
    use std::io::{self, Write};
    io::stdout().flush().unwrap();
    let _ = Command::new(cmd).args(args).output();
    println!("{}", "DONE".green());
}

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
}