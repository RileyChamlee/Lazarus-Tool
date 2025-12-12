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
            "5. SNMP OID Lookup",
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
            4 => snmp_lookup(),
            _ => break,
        }
    }
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

// --- 5. SNMP LOOKUP ---
fn snmp_lookup() {
    println!("{}", "\n[*] SNMP OID LOOKUP TOOL".cyan());
    
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

    let oid_str: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("OID to Query (e.g., 1.3.6.1.2.1.1.1.0)")
        .default("1.3.6.1.2.1.1.1.0".to_string())
        .interact_text()
        .unwrap();

    let oid: Vec<u32> = oid_str.split('.')
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();

    println!("{}", format!("\n    Querying {} on {}...", oid_str, target).yellow());

    let timeout = Duration::from_secs(2);
    
    match SyncSession::new(&target, community.as_bytes(), Some(timeout), 0) {
        // FIX: Changed 'Ok(response)' to 'Ok(mut response)'
        Ok(mut session) => {
            match session.get(&oid) {
                Ok(mut response) => { // <-- Also added 'mut' here just in case
                    if let Some((_oid, val)) = response.varbinds.next() {
                        println!("{}", "\n[SUCCESS] Response Received:".green().bold());
                        match val {
                            Value::OctetString(bytes) => {
                                println!("    String: {}", String::from_utf8_lossy(bytes));
                            },
                            Value::Integer(i) => println!("    Integer: {}", i),
                            Value::Counter32(c) => println!("    Counter32: {}", c),
                            Value::Timeticks(t) => println!("    Timeticks: {}", t),
                            _ => println!("    Value: {:?}", val),
                        }
                    } else {
                        println!("{}", "    [!] No data returned.".red());
                    }
                },
                Err(_) => println!("{}", "    [!] Request Timeout or Error.".red()),
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