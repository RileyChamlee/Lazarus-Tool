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
            "1. Subnet Fingerprinter (IP + Host + Vendor)", // Upgraded
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

// --- 1. SUBNET FINGERPRINTER (V3.0.5 UPGRADE) ---
pub fn subnet_fingerprinter() {
    println!("{}", "\n[*] STARTING ENHANCED ASSET SCANNER...".cyan());
    
    let input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter Subnet (e.g. 192.168.1)")
        .interact_text()
        .unwrap();

    // Input Sanitization
    let parts: Vec<&str> = input.trim().split('.').collect();
    if parts.len() < 3 { 
        println!("{}", "    [!] Invalid format.".red()); 
        pause(); 
        return; 
    }
    let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);

    println!("{}", format!("    Scanning {}.1 - {}.254...", prefix, prefix).yellow());
    println!("    (Resolving Hostnames & OS... This takes ~20 seconds)");

    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    for i in 1..255 {
        let ip = format!("{}.{}", prefix, i);
        let tx = tx.clone();
        
        handles.push(thread::spawn(move || {
            // UPGRADE: Use -a to resolve hostname, -n 1 for single ping, -w 400 for timeout
            let output = Command::new("ping")
                .args(&["-a", "-n", "1", "-w", "400", &ip])
                .output();
            
            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                if stdout.contains("TTL=") {
                    // 1. Get Hostname (New Feature)
                    let hostname = parse_hostname(&stdout, &ip);
                    
                    // 2. Guess OS from TTL (New Feature)
                    let os = parse_ttl_os(&stdout);

                    // 3. Get MAC & Vendor
                    let mac = get_mac_address(&ip);
                    let vendor = lookup_vendor(&mac);
                    
                    let _ = tx.send((ip, mac, hostname, vendor, os));
                }
            }
        }));
        // Throttling to prevent network flood
        thread::sleep(Duration::from_millis(15));
    }

    drop(tx);

    let mut devices: Vec<_> = rx.into_iter().collect();
    // Numeric Sort
    devices.sort_by(|a, b| {
        let oct_a = a.0.split('.').last().unwrap_or("0").parse::<u8>().unwrap_or(0);
        let oct_b = b.0.split('.').last().unwrap_or("0").parse::<u8>().unwrap_or(0);
        oct_a.cmp(&oct_b)
    });

    if devices.is_empty() {
        println!("{}", "    [!] No active hosts found.".red());
    } else {
        println!("\n{:<15} | {:<20} | {:<17} | {}", "IP ADDRESS", "HOSTNAME", "MAC ADDRESS", "INFO");
        println!("{}", "-------------------------------------------------------------------------------".blue());
        
        for (ip, mac, host, vendor, os) in &devices {
            let info = if !vendor.is_empty() { 
                format!("{} ({})", vendor.cyan(), os.dimmed()) 
            } else { 
                format!("{}", os.dimmed()) 
            };
            println!("{:<15} | {:<20} | {:<17} | {}", ip.green(), host, mac.dimmed(), info);
        }
        
        let report = devices.iter()
            .map(|(i,m,h,v,o)| format!("{},{},{},{},{}", i,m,h,v,o))
            .collect::<Vec<String>>()
            .join("\n");
        logger::log_data("Subnet_Scan", &report);
    }
    
    for h in handles { let _ = h.join(); }
    pause();
}

// --- NEW HELPER FUNCTIONS FOR SCANNER ---
fn parse_hostname(output: &str, ip: &str) -> String {
    // Windows Ping Output: "Pinging DESKTOP-XYZ [192.168.1.50]..."
    if let Some(line) = output.lines().next() {
        if let Some(start) = line.find("Pinging ") {
            if let Some(end) = line.find(" [") {
                let host = &line[start+8..end];
                if host != ip { return host.to_string(); }
            }
        }
    }
    "".to_string()
}

fn parse_ttl_os(output: &str) -> String {
    if let Some(pos) = output.find("TTL=") {
        let rest = &output[pos+4..];
        let ttl_str = rest.split_whitespace().next().unwrap_or("0");
        if let Ok(ttl) = ttl_str.parse::<u8>() {
            return match ttl {
                128 => "Windows".to_string(),
                64 => "Linux/Mac".to_string(),
                255 | 254 => "NetGear".to_string(),
                _ => format!("TTL={}", ttl),
            };
        }
    }
    "".to_string()
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
        "00155D" | "0003FF" => "Hyper-V",
        "005056" | "000C29" | "000569" | "001C14" => "VMware",
        "080027" => "VirtualBox",
        "001C42" => "Parallels",
        // EXPANDED DELL LIST
        "C46516" | "C86C3D" | "F04DA2" | "B8CA3A" | "001422" | "F8B156" | "14B31F" | "A4BB6D" | "0016D3" | "001C23" => "Dell",
        // EXPANDED HP LIST
        "D89D67" | "FC15B4" | "3C5282" | "DCD329" | "5065F3" | "C8D3FF" | "009C02" | "00110A" => "HP",
        // EXPANDED INTEL LIST
        "0016E8" | "6C2990" | "D8F883" | "806E6F" | "4CBB58" | "001B21" => "Intel",
        // APPLE
        "ACBC32" | "1499E2" | "3C15C2" | "F01898" | "BC926B" | "88E9FE" | "F4F951" | "000393" | "000502" => "Apple",
        // NETWORKING
        "00D02D" | "002545" | "F866F2" | "5897BD" | "BC1665" => "Cisco",
        "E0553D" | "00180A" | "AC17C8" => "Meraki",
        "F09E63" | "B4FBE4" | "802AA8" | "7483C2" | "E063DA" | "68D79A" => "Ubiquiti",
        "18B169" | "C025E9" | "2CEA7F" => "SonicWall",
        "A05272" => "Peplink",
        "000B86" | "D8C7C8" | "9C1C12" | "204C03" => "Aruba",
        "E02F6D" | "80CC28" | "9C3DCF" => "Netgear",
        "B827EB" | "DC1660" | "D83ADD" | "E45F01" => "Raspberry Pi",
        _ => "",
    }.to_string()
}

// --- 2. WI-FI OPERATIONS (RESTORED FULL) ---
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

// --- 3. NETWORK NUKE (RESTORED FULL) ---
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

// --- REMAINING FUNCTIONS (UNCHANGED) ---
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