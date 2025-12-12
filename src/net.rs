use crate::logger;
use colored::*;
use dialoguer::{Select, Input, theme::ColorfulTheme};
use std::process::Command;
use std::time::Duration;
use std::thread;
use std::sync::mpsc;
use snmp::{SyncSession, Value};

pub fn menu() {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "--- NETWORK TOOLS ---".cyan().bold());

        let choices = &[
            "1. Subnet Fingerprinter (IP + MAC + Vendor)", // <-- Renamed
            "2. Network Nuke (Reset Stack)",
            "3. Connectivity Test (Ping Google/Cloudflare)",
            "4. Save IP Configuration to Log",
            "5. SNMP Walk (Discover OIDs)",
            "Back",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select Action")
            .default(0)
            .items(&choices[..])
            .interact()
            .unwrap();

        match selection {
            0 => subnet_fingerprinter(),
            1 => network_nuke(),
            2 => connectivity_test(),
            3 => save_ip_log(),
            4 => snmp_walk(),
            _ => break,
        }
    }
}

// --- 1. SUBNET FINGERPRINTER (UPGRADED) ---
fn subnet_fingerprinter() {
    println!("{}", "\n[*] STARTING ASSET SCANNER...".cyan());
    
    let prefix: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter Subnet Prefix (e.g., 192.168.1)")
        .interact_text()
        .unwrap();

    println!("{}", format!("    Scanning {}.1 - {}.254...", prefix, prefix).yellow());
    println!("    (Pinging hosts and resolving MAC addresses...)\n");

    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    // 1. Threaded Scan
    for i in 1..255 {
        let ip = format!("{}.{}", prefix, i);
        let tx = tx.clone();
        
        let handle = thread::spawn(move || {
            // Ping to populate ARP table
            let output = Command::new("ping")
                .args(&["-n", "1", "-w", "100", &ip])
                .output();
                
            if let Ok(out) = output {
                if String::from_utf8_lossy(&out.stdout).contains("TTL=") {
                    // Host is up, now get MAC info
                    let mac = get_mac_address(&ip);
                    let vendor = lookup_vendor(&mac);
                    let _ = tx.send((ip, mac, vendor));
                }
            }
        });
        handles.push(handle);
    }

    drop(tx);

    // 2. Collect Results
    let mut devices = Vec::new();
    for device in rx {
        devices.push(device);
    }

    // 3. Sort by IP (naive string sort, usually good enough for display)
    devices.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));

    // 4. Display Table
    if devices.is_empty() {
        println!("{}", "    [!] No active hosts found.".red());
    } else {
        println!("{:<16} | {:<18} | {}", "IP ADDRESS", "MAC ADDRESS", "VENDOR/DEVICE");
        println!("{}", "-------------------------------------------------------------".blue());
        
        for (ip, mac, vendor) in &devices {
            println!("{:<16} | {:<18} | {}", ip.green(), mac.dimmed(), vendor.cyan());
        }
        
        // Log it
        let report = devices.iter()
            .map(|(i, m, v)| format!("{} - {} - {}", i, m, v))
            .collect::<Vec<String>>()
            .join("\n");
        logger::log_data("Subnet_Fingerprint", &report);
    }
    
    for h in handles {
        let _ = h.join();
    }
    pause();
}

// --- HELPER: GET MAC ---
fn get_mac_address(ip: &str) -> String {
    // Run 'arp -a [IP]' to pull from Windows ARP cache
    let output = Command::new("arp")
        .arg("-a")
        .arg(ip)
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        // Look for pattern xx-xx-xx-xx-xx-xx
        for line in stdout.lines() {
            if line.contains(ip) {
                // The output usually looks like:  192.168.1.50   b8-27-eb-1a-2b-3c   dynamic
                // We split by whitespace and find the part with dashes
                for part in line.split_whitespace() {
                    if part.contains('-') && part.len() == 17 {
                        return part.to_string().to_uppercase();
                    }
                }
            }
        }
    }
    "Unknown".to_string()
}

// --- HELPER: MINI VENDOR DB ---
fn lookup_vendor(mac: &str) -> String {
    if mac == "Unknown" { return "".to_string(); }
    
    // Normalize MAC (remove dashes/colons, take first 6 chars)
    let prefix = mac.replace("-", "").replace(":", "");
    if prefix.len() < 6 { return "".to_string(); }
    let oui = &prefix[0..6];

    // Simple common list (You can expand this!)
    match oui {
        // Virtual / Microsoft
        "00155D" => "Microsoft Hyper-V",
        "0003FF" => "Microsoft Hyper-V",
        "005056" | "000C29" | "000569" => "VMware",
        // PC Vendors
        "F04DA2" | "B8CA3A" | "001422" | "F8B156" => "Dell",
        "D89D67" | "FC15B4" | "3C5282" | "DCD329" => "HP / Hewlett Packard",
        "54E1AD" | "482AE3" | "B4A9FC" => "Lenovo",
        // Apple
        "ACBC32" | "1499E2" | "3C15C2" | "F01898" => "Apple Device",
        // Networking / IoT
        "F09E63" | "B4FBE4" | "802AA8" | "7483C2" => "Ubiquiti",
        "001565" | "9C93E4" => "Xerox",
        "B827EB" | "DC1660" | "D83ADD" => "Raspberry Pi",
        "001132" => "Synology",
        "00408C" => "Axis Communications",
        "00D02D" => "Cisco",
        _ => "Unknown Vendor",
    }
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

// --- 5. SNMP WALK ---
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

    let root_oid_str: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Start Walking at OID (Default: System Info)")
        .default("1.3.6.1.2.1.1".to_string()) 
        .interact_text()
        .unwrap();

    let root_oid: Vec<u32> = root_oid_str.split('.')
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();

    println!("{}", format!("\n    Scanning {} starting at {}...", target, root_oid_str).yellow());
    println!("{}", "    (Press Ctrl+C to stop if it goes on forever)\n".dimmed());

    let timeout = Duration::from_secs(2);
    
    match SyncSession::new(&target, community.as_bytes(), Some(timeout), 0) {
        Ok(mut session) => {
            let mut current_oid = root_oid.clone();
            let mut count = 0;

            loop {
                match session.getnext(&current_oid) {
                    Ok(mut response) => {
                        if let Some((next_oid_struct, val)) = response.varbinds.next() {
                            
                            let next_oid_string = next_oid_struct.to_string();

                            if !next_oid_string.starts_with(&root_oid_str) {
                                break;
                            }

                            match val {
                                Value::OctetString(bytes) => {
                                    let s = String::from_utf8_lossy(bytes);
                                    if s.chars().any(|c| c.is_control() && !c.is_whitespace()) {
                                        println!("    {} = [Binary Data]", next_oid_string);
                                    } else {
                                        println!("    {} = {}", next_oid_string.green(), s);
                                    }
                                },
                                Value::Integer(i) => println!("    {} = {} (Int)", next_oid_string.green(), i),
                                Value::Counter32(c) => println!("    {} = {} (Counter)", next_oid_string.green(), c),
                                Value::Timeticks(t) => println!("    {} = {} (Ticks)", next_oid_string.green(), t),
                                _ => println!("    {} = {:?}", next_oid_string.green(), val),
                            }

                            current_oid = next_oid_string.split('.')
                                .filter_map(|s| s.parse::<u32>().ok())
                                .collect();
                            
                            count += 1;

                            if count >= 100 {
                                println!("{}", "    --- (Limit reached: 100 items) ---".yellow());
                                break;
                            }
                        } else {
                            break;
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

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
}