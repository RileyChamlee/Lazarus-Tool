use crate::logger;
use colored::*;
use dialoguer::{Select, Input, theme::ColorfulTheme};
use std::process::Command;
use std::time::Duration;
use std::thread;
use std::sync::mpsc;
use std::fs;
use snmp::{SyncSession, Value};

pub fn menu() {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "--- NETWORK TOOLS ---".cyan().bold());

        let choices = &[
            "1. Subnet Fingerprinter (IP + MAC + Vendor)", // Upgraded
            "2. Wi-Fi Operations (Clone/Import/Export)", // NEW
            "3. Network Nuke (Reset Stack)",
            "4. Connectivity Test (Ping Google/Cloudflare)",
            "5. Save IP Configuration to Log",
            "6. SNMP Walk (Discover OIDs)",
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
            1 => wifi_menu(),
            2 => network_nuke(),
            3 => connectivity_test(),
            4 => save_ip_log(),
            5 => snmp_walk(),
            _ => break,
        }
    }
}

fn wifi_menu() {
    loop {
        let choices = &[
            "1. Show Current Wi-Fi Password (Harvest)",
            "2. Export All Profiles (Migration)",
            "3. Import Profiles from Folder",
            "Back"
        ];
        
        let sel = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("WI-FI OPERATIONS")
            .items(&choices[..])
            .interact()
            .unwrap();
            
        match sel {
            0 => wifi_show_current_password(),
            1 => wifi_export_profiles(),
            2 => wifi_import_profiles(),
            _ => break,
        }
    }
}

fn wifi_show_current_password() {
    println!("{}", "\n[*] RETRIEVING WI-FI KEYS...".cyan());
    let cmd = "netsh wlan show profile name=* key=clear";
    let output = Command::new("cmd").args(&["/C", cmd]).output().expect("Failed");
    println!("{}", String::from_utf8_lossy(&output.stdout));
    pause();
}

fn wifi_export_profiles() {
    println!("{}", "\n[*] EXPORTING WI-FI PROFILES...".cyan());
    let path: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Export Destination Folder")
        .default("C:\\Lazarus_WiFi_Backup".to_string())
        .interact_text()
        .unwrap();

    let _ = fs::create_dir_all(&path);
    
    let status = Command::new("netsh")
        .args(&["wlan", "export", "profile", &format!("folder={}", path), "key=clear"])
        .status();

    if status.is_ok() {
        println!("{}", format!("[SUCCESS] Profiles saved to {}", path).green());
    } else {
        println!("{}", "[FAIL] Could not export profiles.".red());
    }
    pause();
}

fn wifi_import_profiles() {
    println!("{}", "\n[*] IMPORTING WI-FI PROFILES...".cyan());
    let path_str: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Source Folder containing XML files")
        .interact_text()
        .unwrap();
        
    let path = std::path::Path::new(&path_str);
    if !path.exists() { println!("{}", "    [!] Folder not found.".red()); pause(); return; }

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(ext) = p.extension() {
                if ext == "xml" {
                    print!("    Importing {:?}... ", p.file_name().unwrap());
                    let _ = Command::new("netsh")
                        .args(&["wlan", "add", "profile", &format!("filename={:?}", p)])
                        .output();
                    println!("{}", "DONE".green());
                }
            }
        }
    }
    pause();
}

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

    for i in 1..255 {
        let ip = format!("{}.{}", prefix, i);
        let tx = tx.clone();
        
        let handle = thread::spawn(move || {
            let output = Command::new("ping")
                .args(&["-n", "1", "-w", "100", &ip])
                .output();
                
            if let Ok(out) = output {
                if String::from_utf8_lossy(&out.stdout).contains("TTL=") {
                    let mac = get_mac_address(&ip);
                    let vendor = lookup_vendor(&mac);
                    let _ = tx.send((ip, mac, vendor));
                }
            }
        });
        handles.push(handle);
    }

    drop(tx);

    let mut devices = Vec::new();
    for device in rx {
        devices.push(device);
    }

    devices.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));

    if devices.is_empty() {
        println!("{}", "    [!] No active hosts found.".red());
    } else {
        println!("{:<16} | {:<18} | {}", "IP ADDRESS", "MAC ADDRESS", "VENDOR/DEVICE");
        println!("{}", "-------------------------------------------------------------".blue());
        
        for (ip, mac, vendor) in &devices {
            println!("{:<16} | {:<18} | {}", ip.green(), mac.dimmed(), vendor.cyan());
        }
        
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

fn get_mac_address(ip: &str) -> String {
    let output = Command::new("arp").arg("-a").arg(ip).output();
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if line.contains(ip) {
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

fn lookup_vendor(mac: &str) -> String {
    if mac == "Unknown" { return "".to_string(); }
    let prefix = mac.replace("-", "").replace(":", "");
    if prefix.len() < 6 { return "".to_string(); }
    let oui = &prefix[0..6];

    match oui {
        "00155D" | "0003FF" => "Microsoft Hyper-V".to_string(),
        "005056" | "000C29" | "000569" => "VMware".to_string(),
        "F04DA2" | "B8CA3A" | "001422" | "F8B156" => "Dell".to_string(),
        "D89D67" | "FC15B4" | "3C5282" | "DCD329" => "HP / Hewlett Packard".to_string(),
        "54E1AD" | "482AE3" | "B4A9FC" => "Lenovo".to_string(),
        "ACBC32" | "1499E2" | "3C15C2" | "F01898" => "Apple Device".to_string(),
        "F09E63" | "B4FBE4" | "802AA8" | "7483C2" => "Ubiquiti".to_string(),
        "001565" | "9C93E4" => "Xerox".to_string(),
        "B827EB" | "DC1660" | "D83ADD" => "Raspberry Pi".to_string(),
        "001132" => "Synology".to_string(),
        "00408C" => "Axis Communications".to_string(),
        "00D02D" => "Cisco".to_string(),
        _ => "Unknown Vendor".to_string(),
    }
}

fn network_nuke() {
    println!("{}", "\n[*] INITIATING NETWORK NUKE...".red().bold());
    let cmds = ["netsh winsock reset", "netsh int ip reset", "ipconfig /release", "ipconfig /renew", "ipconfig /flushdns"];
    for cmd in cmds {
        print!("    Exec: '{}'... ", cmd);
        let _ = Command::new("cmd").args(&["/C", cmd]).output();
        println!("{}", "DONE".green());
    }
    println!("{}", "\n[DONE] Network stack reset. You may need to reboot.".green());
    pause();
}

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

fn save_ip_log() {
    println!("{}", "\n[*] SAVING IP CONFIGURATION...".cyan());
    let output = Command::new("ipconfig").arg("/all").output().expect("Failed");
    let content = String::from_utf8_lossy(&output.stdout).to_string();
    println!("{}", &content);
    logger::log_data("IP_Configuration", &content);
    println!("{}", "\n[+] Configuration saved to Lazarus_Reports folder.".green());
    pause();
}

fn snmp_walk() {
    println!("{}", "\n[*] SNMP WALKER (DISCOVERY TOOL)".cyan());
    
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
        .with_prompt("Start Walking at OID")
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
                            if !next_oid_string.starts_with(&root_oid_str) { break; }
                            
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
                                _ => println!("    {} = {:?}", next_oid_string.green(), val),
                            }
                            current_oid = next_oid_string.split('.').filter_map(|s| s.parse::<u32>().ok()).collect();
                            count += 1;
                            if count >= 100 { 
                                println!("{}", "    --- (Limit reached) ---".yellow()); 
                                break; 
                            }
                        } else { break; }
                    },
                    Err(_) => break,
                }
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