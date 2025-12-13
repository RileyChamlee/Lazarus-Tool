use crate::logger;
use colored::*;
use dialoguer::{Select, Input, Confirm, theme::ColorfulTheme};
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
            "1. Subnet Fingerprinter (IP + MAC + Vendor)",
            "2. Wi-Fi Operations (Clone/Import/Export)", 
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

pub fn wifi_menu() {
    loop {
        let choices = &[
            "1. Show Current Wi-Fi Password (Harvest)",
            "2. Export All Profiles (Migration)",
            "3. Import Profiles from Folder",
            "Back"
        ];
        let sel = Select::with_theme(&ColorfulTheme::default()).with_prompt("WI-FI OPERATIONS").items(&choices[..]).interact().unwrap();
        match sel {
            0 => wifi_show_current_password(),
            1 => wifi_export_profiles(),
            2 => wifi_import_profiles(),
            _ => break,
        }
    }
}

pub fn wifi_show_current_password() {
    println!("{}", "\n[*] RETRIEVING WI-FI KEYS...".cyan());
    let cmd = "netsh wlan show profile name=* key=clear";
    let output = Command::new("cmd").args(&["/C", cmd]).output().expect("Failed");
    println!("{}", String::from_utf8_lossy(&output.stdout));
    pause();
}

pub fn wifi_export_profiles() {
    println!("{}", "\n[*] EXPORTING WI-FI PROFILES...".cyan());
    let path: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Export Destination Folder").default("C:\\Lazarus_WiFi_Backup".to_string()).interact_text().unwrap();
    let _ = fs::create_dir_all(&path);
    let status = Command::new("netsh").args(&["wlan", "export", "profile", &format!("folder={}", path), "key=clear"]).status();
    if status.is_ok() { println!("{}", format!("[SUCCESS] Profiles saved to {}", path).green()); } 
    else { println!("{}", "[FAIL] Could not export profiles.".red()); }
    pause();
}

pub fn wifi_import_profiles() {
    println!("{}", "\n[*] IMPORTING WI-FI PROFILES...".cyan());
    let path_str: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Source Folder").interact_text().unwrap();
    let path = std::path::Path::new(&path_str);
    if !path.exists() { println!("{}", "    [!] Folder not found.".red()); pause(); return; }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(ext) = p.extension() {
                if ext == "xml" {
                    print!("    Importing {:?}... ", p.file_name().unwrap());
                    let _ = Command::new("netsh").args(&["wlan", "add", "profile", &format!("filename={:?}", p)]).output();
                    println!("{}", "DONE".green());
                }
            }
        }
    }
    pause();
}

pub fn subnet_fingerprinter() {
    println!("{}", "\n[*] STARTING ASSET SCANNER...".cyan());
    
    let input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter Subnet (e.g. 192.168.1 or 10.0.0.1)")
        .interact_text()
        .unwrap();

    // Input Sanitization (Fixes the 10.0.0.1.1 bug)
    let parts: Vec<&str> = input.trim().split('.').collect();
    let prefix = if parts.len() == 4 {
        format!("{}.{}.{}", parts[0], parts[1], parts[2])
    } else if parts.len() == 3 {
        input.trim().to_string()
    } else {
        println!("{}", "    [!] Invalid IP format. Please use format like 192.168.1".red());
        pause();
        return;
    };

    println!("{}", format!("    Scanning {}.1 - {}.254...", prefix, prefix).yellow());
    println!("    (Pinging hosts... This may take up to 20 seconds)");

    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    // Thread Throttling enabled
    for i in 1..255 {
        let ip = format!("{}.{}", prefix, i);
        let tx = tx.clone();
        
        let handle = thread::spawn(move || {
            let output = Command::new("ping")
                .args(&["-n", "1", "-w", "500", &ip])
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
        thread::sleep(Duration::from_millis(15)); 
    }

    drop(tx);

    let mut devices = Vec::new();
    for device in rx {
        devices.push(device);
    }

    // Numeric Sort
    devices.sort_by(|a, b| {
        let octet_a = a.0.split('.').last().unwrap_or("0").parse::<u8>().unwrap_or(0);
        let octet_b = b.0.split('.').last().unwrap_or("0").parse::<u8>().unwrap_or(0);
        octet_a.cmp(&octet_b)
    });

    if devices.is_empty() {
        println!("{}", "    [!] No active hosts found.".red());
    } else {
        println!("\n{:<16} | {:<18} | {}", "IP ADDRESS", "MAC ADDRESS", "VENDOR/DEVICE");
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
                    if part.contains('-') && part.len() == 17 { return part.to_string().to_uppercase(); }
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
        "005056" | "000C29" | "000569" | "001C14" => "VMware".to_string(),
        "080027" => "VirtualBox".to_string(),
        "001C42" => "Parallels".to_string(),
        "F04DA2" | "B8CA3A" | "001422" | "F8B156" | "14B31F" | "A4BB6D" => "Dell".to_string(),
        "D89D67" | "FC15B4" | "3C5282" | "DCD329" | "5065F3" | "C8D3FF" => "HP / Hewlett Packard".to_string(),
        "54E1AD" | "482AE3" | "B4A9FC" | "002324" | "6C8814" => "Lenovo".to_string(),
        "2816A8" | "501AC5" | "989096" => "Microsoft Surface".to_string(),
        "ACBC32" | "1499E2" | "3C15C2" | "F01898" | "BC926B" | "88E9FE" | "F4F951" => "Apple Device".to_string(),
        "D8F883" | "806E6F" | "4CBB58" => "Intel Corp".to_string(),
        "00D861" | "049226" | "D43D7E" => "Micro-Star (MSI)".to_string(),
        "F4B7E2" | "04D4C4" => "ASUS".to_string(),
        "00D02D" | "002545" | "F866F2" | "5897BD" | "BC1665" => "Cisco".to_string(),
        "E0553D" | "00180A" | "AC17C8" => "Cisco Meraki".to_string(),
        "F09E63" | "B4FBE4" | "802AA8" | "7483C2" | "E063DA" | "68D79A" => "Ubiquiti".to_string(),
        "18B169" | "C025E9" | "2CEA7F" => "SonicWall".to_string(),
        "000B86" | "D8C7C8" | "9C1C12" | "204C03" => "Aruba Networks".to_string(),
        "E02F6D" | "80CC28" | "9C3DCF" => "Netgear".to_string(),
        "50C7BF" | "704F57" | "18A6F7" | "F4F26D" => "TP-Link".to_string(),
        "001132" | "00248C" | "9009D0" => "Synology".to_string(),
        "0090A8" | "000129" => "Zyxel".to_string(),
        "DC9FDB" | "F07959" => "Fortinet".to_string(),
        "001565" | "9C93E4" | "0000AA" => "Xerox".to_string(),
        "30055C" | "008077" | "A402B9" => "Brother".to_string(),
        "001E8F" | "84BA3B" | "F0038C" => "Canon".to_string(),
        "00C0EE" | "489EBD" => "Kyocera".to_string(),
        "002673" | "905BA3" => "Ricoh".to_string(),
        "AC3FA4" | "D83064" => "Zebra Technologies".to_string(),
        "B827EB" | "DC1660" | "D83ADD" | "E45F01" => "Raspberry Pi".to_string(),
        "649EF3" | "0004F2" => "Polycom".to_string(),
        "805EC0" | "001565" => "Yealink".to_string(),
        "000B82" | "009033" => "Grandstream".to_string(),
        "00408C" | "ACCC8E" => "Axis Communications".to_string(),
        "102C6B" | "4437E6" => "Hikvision".to_string(),
        "2462AB" | "807D3A" => "Espressif (IoT)".to_string(),
        _ => "".to_string(),
    }
}

pub fn network_nuke() {
    println!("{}", "\n[!] WARNING: NETWORK NUKE INITIATED [!]".red().bold());
    println!("    This will reset all network adapters, clear DNS, and remove static IPs.");
    println!("    (A backup of your current IP config will be saved first.)");
    
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Are you sure you want to proceed?")
        .default(false)
        .interact()
        .unwrap() 
    {
        return;
    }

    // Backup Phase
    println!("{}", "\n[*] Backing up current network configuration...".yellow());
    let backup_cmd = "netsh interface ip show config";
    let output = Command::new("cmd").args(&["/C", backup_cmd]).output();
    
    match output {
        Ok(o) => {
            let content = String::from_utf8_lossy(&o.stdout).to_string();
            logger::log_data("Network_Config_Backup", &content);
            println!("{}", "    [+] Configuration backed up to Lazarus_Reports.".green());
        },
        Err(_) => println!("{}", "    [!] Backup failed (continuing anyway)...".red()),
    }

    // Nuke Phase
    println!("{}", "\n[*] Resetting Network Stack...".cyan());
    let cmds = [
        "netsh winsock reset", 
        "netsh int ip reset", 
        "ipconfig /release", 
        "ipconfig /renew", 
        "ipconfig /flushdns"
    ];

    for cmd in cmds {
        print!("    Exec: '{}'... ", cmd);
        let _ = Command::new("cmd").args(&["/C", cmd]).output();
        println!("{}", "DONE".green());
    }
    
    println!("{}", "\n[DONE] Network stack reset. You MUST reboot for changes to take effect.".green().bold());
    pause();
}

pub fn connectivity_test() {
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

pub fn save_ip_log() {
    println!("{}", "\n[*] SAVING IP CONFIGURATION...".cyan());
    let output = Command::new("ipconfig").arg("/all").output().expect("Failed");
    let content = String::from_utf8_lossy(&output.stdout).to_string();
    println!("{}", &content);
    logger::log_data("IP_Configuration", &content);
    println!("{}", "\n[+] Saved.".green());
    pause();
}

pub fn snmp_walk() {
    println!("{}", "\n[*] SNMP WALKER...".cyan());
    let target: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Target IP").default("127.0.0.1".to_string()).interact_text().unwrap();
    let community: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Community").default("public".to_string()).interact_text().unwrap();
    let root_oid_str: String = Input::with_theme(&ColorfulTheme::default()).with_prompt("Start OID").default("1.3.6.1.2.1.1".to_string()).interact_text().unwrap();
    let root_oid: Vec<u32> = root_oid_str.split('.').filter_map(|s| s.parse::<u32>().ok()).collect();
    println!("{}", "    Scanning...".yellow());
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
                            println!("    {} = {:?}", next_oid_string.green(), val);
                            current_oid = next_oid_string.split('.').filter_map(|s| s.parse::<u32>().ok()).collect();
                            count += 1;
                            if count >= 100 { break; }
                        } else { break; }
                    },
                    Err(_) => break,
                }
            }
        },
        Err(_) => println!("{}", "    [!] SNMP Fail.".red()),
    }
    pause();
}

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
}