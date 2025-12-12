use crate::logger;
use colored::*;
use dialoguer::{Select, Input, theme::ColorfulTheme};
use std::process::Command;
use std::time::Duration;
use std::thread;
use snmp::{SyncSession, Value};

pub fn menu() {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "--- NETWORK TOOLS ---".cyan().bold());

        let choices = &[
            "1. Subnet Scanner (Find Active IPs)",
            "2. Network Nuke (Reset Stack)",
            "3. Connectivity Test (Ping Google/Cloudflare)",
            "4. Save IP Configuration to Log",
            "5. SNMP Walk (Discover OIDs)", // Renamed
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
            1 => network_nuke(),
            2 => connectivity_test(),
            3 => save_ip_log(),
            4 => snmp_walk(), // Calls the new walker
            _ => break,
        }
    }
}

// --- 5. SNMP WALK (NEW: Discovers OIDs) ---
fn snmp_walk() {
    println!("{}", "\n[*] SNMP WALKER (DISCOVERY TOOL)".cyan());
    println!("    (This will list all available OIDs starting from your root)");
    
    let target: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Target IP Address")
        .default("127.0.0.1".to_string())
        .interact_text()
        .unwrap();

    let community: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Community String")
        .default("public".to_string())
        .interact_text()
        .unwrap();

    // Default to 'system' branch, which is safe and usually exists
    let root_oid_str: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Start Walking at OID (Default: System Info)")
        .default("1.3.6.1.2.1.1".to_string()) 
        .interact_text()
        .unwrap();

    let root_oid: Vec<u32> = root_oid_str.split('.')
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();

    println!("{}", format!("\n    Scanning {} starting at {}...", target, root_oid_str).yellow());
    println!("{}", "    (Press Ctrl+C to stop if it goes on forever)\n".gray());

    let timeout = Duration::from_secs(2);
    
    match SyncSession::new(&target, community.as_bytes(), Some(timeout), 0) {
        Ok(mut session) => {
            let mut current_oid = root_oid.clone();
            let mut count = 0;

            loop {
                // GETNEXT is the magic command that finds the "next" OID for you
                match session.getnext(&current_oid) {
                    Ok(mut response) => {
                        if let Some((next_oid, val)) = response.varbinds.next() {
                            // Check if we have stepped outside the tree we wanted to scan
                            if next_oid.len() < root_oid.len() || &next_oid[0..root_oid.len()] != &root_oid[..] {
                                break;
                            }

                            // Print the Result
                            let oid_string = next_oid.iter().map(|i| i.to_string()).collect::<Vec<String>>().join(".");
                            
                            match val {
                                Value::OctetString(bytes) => {
                                    // Try to print strings cleanly
                                    let s = String::from_utf8_lossy(bytes);
                                    // If it looks like garbage characters, print raw bytes
                                    if s.chars().any(|c| c.is_control() && !c.is_whitespace()) {
                                        println!("    {} = [Binary Data]", oid_string);
                                    } else {
                                        println!("    {} = {}", oid_string.green(), s);
                                    }
                                },
                                Value::Integer(i) => println!("    {} = {} (Int)", oid_string.green(), i),
                                Value::Counter32(c) => println!("    {} = {} (Counter)", oid_string.green(), c),
                                Value::Timeticks(t) => println!("    {} = {} (Ticks)", oid_string.green(), t),
                                _ => println!("    {} = {:?}", oid_string.green(), val),
                            }

                            // Update loop to look for the next one
                            current_oid = next_oid;
                            count += 1;

                            // Safety break to prevent infinite loops on weird devices
                            if count >= 100 {
                                println!("{}", "    --- (Limit reached: 100 items) ---".yellow());
                                break;
                            }
                        } else {
                            break; // End of tree
                        }
                    },
                    Err(_) => {
                        println!("{}", "    [!] Scan ended (Timeout or End of MIB).".red());
                        break;
                    }
                }
            }
            if count == 0 {
                 println!("{}", "    [!] No OIDs found. (Check IP, Community String, or Firewall)".red());
            }
        },
        Err(_) => println!("{}", "    [!] Could not create SNMP session.".red()),
    }
    pause();
}

// --- 1. SUBNET SCANNER ---
fn subnet_scanner() {
    println!("{}", "\n[*] STARTING SUBNET SCANNER...".cyan());
    
    let prefix: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter Subnet Prefix (e.g., 192.168.1)")
        .interact_text()
        .unwrap();

    println!("{}", format!("    Scanning {}.1 - {}.254 (This takes a moment)...", prefix, prefix).yellow());

    let mut handles = vec![];
    let (tx, rx) = std::sync::mpsc::channel();

    for i in 1..255 {
        let ip = format!("{}.{}", prefix, i);
        let tx = tx.clone();
        
        let handle = thread::spawn(move || {
            let output = Command::new("ping")
                .args(&["-n", "1", "-w", "100", &ip])
                .output();
                
            if let Ok(out) = output {
                if String::from_utf8_lossy(&out.stdout).contains("TTL=") {
                    let _ = tx.send(ip);
                }
            }
        });
        handles.push(handle);
    }

    drop(tx);

    let mut active_ips = Vec::new();
    for ip in rx {
        println!("    [+] Found Active Host: {}", ip.green());
        active_ips.push(ip);
    }

    for h in handles {
        let _ = h.join();
    }

    if active_ips.is_empty() {
        println!("{}", "    [!] No active hosts found.".red());
    } else {
        logger::log_data("Subnet_Scan", &format!("Active IPs on {}.x:\n{:?}", prefix, active_ips));
    }
    pause();
}

// --- 2. NETWORK NUKE ---
fn network_nuke() {
    println!("{}", "\n[*] INITIATING NETWORK NUKE...".red().bold());
    println!("    (Resets Winsock, IP Stack, and flushes DNS)");

    let cmds = [
        "netsh winsock reset",
        "netsh int ip reset",
        "ipconfig /release",
        "ipconfig /renew",
        "ipconfig /flushdns",
    ];

    for cmd in cmds {
        print!("    Exec: '{}'... ", cmd);
        let _ = Command::new("cmd").args(&["/C", cmd]).output();
        println!("{}", "DONE".green());
    }
    
    println!("{}", "\n[DONE] Network stack reset. You may need to reboot.".green());
    pause();
}

// --- 3. CONNECTIVITY TEST ---
fn connectivity_test() {
    println!("{}", "\n[*] RUNNING CONNECTIVITY TEST...".cyan());
    
    let targets = [("8.8.8.8", "Google DNS"), ("1.1.1.1", "Cloudflare DNS")];

    for (ip, name) in targets.iter() {
        print!("    Pinging {} ({})... ", name, ip);
        let status = Command::new("ping").args(&["-n", "1", ip]).status();
        
        if status.is_ok() && status.unwrap().success() {
            println!("{}", "ONLINE".green().bold());
        } else {
            println!("{}", "UNREACHABLE".red().bold());
        }
    }
    pause();
}

// --- 4. SAVE IP CONFIG ---
fn save_ip_log() {
    println!("{}", "\n[*] SAVING IP CONFIGURATION...".cyan());
    
    let output = Command::new("ipconfig").arg("/all").output().expect("Failed to run ipconfig");
    let content = String::from_utf8_lossy(&output.stdout).to_string();
    
    println!("{}", &content);
    logger::log_data("IP_Configuration", &content);
    println!("{}", "\n[+] Configuration saved to Lazarus_Reports folder.".green());
    pause();
}

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
}