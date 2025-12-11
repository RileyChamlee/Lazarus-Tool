use crate::logger;
use colored::*;
use dialoguer::{Select, theme::ColorfulTheme};
use std::process::Command;

pub fn menu() {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "--- DOMAIN & IDENTITY TOOLS ---".cyan().bold());

        let choices = &[
            "1. Analyze Domain Trust (Secure Channel)",
            "2. Repair Domain Trust (Attempt Fix)",
            "3. Force Group Policy Update (GPUpdate)",
            "4. Audit Applied Policies (GPResult)",
            "5. Force Azure AD Connect Sync (Delta)", // NEW
            "6. Find Locked Out Users", // NEW
            "Back",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select Action")
            .default(0)
            .items(&choices[..])
            .interact()
            .unwrap();

        match selection {
            0 => check_trust(),
            1 => repair_trust(),
            2 => force_gpupdate(),
            3 => audit_gpo(),
            4 => force_adsync(),
            5 => list_locked_users(),
            _ => break,
        }
    }
}

// --- NEW FEATURES ---

fn force_adsync() {
    println!("{}", "\n[*] TRIGGERING AZURE AD DELTA SYNC...".cyan());
    println!("    (Note: This must be run on the server with AD Connect installed)");

    let ps_cmd = r#"
    try {
        Import-Module ADSync -ErrorAction Stop
        Start-ADSyncSyncCycle -PolicyType Delta
        Write-Output "SUCCESS: Delta sync cycle started."
    } catch {
        Write-Error "FAILED: Could not load ADSync module. Are you on the Sync Server?"
    }
    "#;

    let output = Command::new("powershell")
        .args(&["-Command", ps_cmd])
        .output()
        .expect("Failed to execute PowerShell");

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !stdout.is_empty() {
        println!("    [+] {}", stdout.green());
    }
    if !stderr.is_empty() {
        println!("    [!] Error: {}", stderr.red());
    }
    pause();
}

fn list_locked_users() {
    println!("{}", "\n[*] SCANNING FOR LOCKED AD ACCOUNTS...".cyan());

    // Requires ActiveDirectory PowerShell module (RSAT)
    let ps_cmd = r#"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $Locked = Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, LastLogonDate
        if ($Locked) {
            $Locked | Format-Table -AutoSize
        } else {
            Write-Output "No locked accounts found."
        }
    } catch {
        Write-Error "FAILED: RSAT ActiveDirectory module not found."
    }
    "#;

    let output = Command::new("powershell")
        .args(&["-Command", ps_cmd])
        .output()
        .expect("Failed to scan AD");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !stdout.is_empty() {
        println!("{}", stdout);
        logger::log_data("Locked_Users", &stdout);
    }
    if !stderr.contains("FAILED") && !stderr.trim().is_empty() {
         // PowerShell sometimes puts table headers in stderr stream depending on formatting
         println!("{}", stderr);
    } else if stderr.contains("FAILED") {
        println!("    [!] {}", stderr.trim().red());
    }
    
    pause();
}

// --- EXISTING FEATURES ---

fn check_trust() {
    println!("{}", "\n[*] TESTING SECURE CHANNEL...".cyan());
    // Test-ComputerSecureChannel returns "True" or "False"
    let output = Command::new("powershell")
        .args(&["-Command", "Test-ComputerSecureChannel"])
        .output()
        .expect("Failed to run test");

    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if result == "True" {
        println!("{}", "    [+] Trust Relationship: HEALTHY".green().bold());
    } else {
        println!("{}", "    [!] Trust Relationship: BROKEN".red().bold());
        println!("    (User logins may fail. Try 'Repair Domain Trust' next.)");
    }
    pause();
}

fn repair_trust() {
    println!("{}", "\n[*] ATTEMPTING TRUST REPAIR...".yellow());
    println!("    (This attempts to reset the machine account password with the DC)");

    // We run with -Repair. Note: If the trust is totally gone, this might require domain admin creds.
    let output = Command::new("powershell")
        .args(&["-Command", "Test-ComputerSecureChannel -Repair -Verbose"])
        .output()
        .expect("Failed to run repair");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if stdout.contains("True") {
        println!("{}", "    [+] REPAIR SUCCESSFUL. Trust restored.".green().bold());
    } else {
        println!("{}", "    [!] Repair Failed.".red());
        println!("    Error Details: {}", stderr.yellow());
        println!("    (You may need to unjoin/rejoin manually or use a Domain Admin shell.)");
    }
    pause();
}

fn force_gpupdate() {
    println!("{}", "\n[*] FORCING GROUP POLICY UPDATE...".cyan());
    
    // We spawn it so the user sees the standard Windows output lines
    let mut child = Command::new("gpupdate")
        .arg("/force")
        .spawn()
        .expect("Failed to launch gpupdate");

    let _ = child.wait();
    
    println!("{}", "\n[DONE] Policy update attempted.".green());
    pause();
}

fn audit_gpo() {
    println!("{}", "\n[*] GATHERING GROUP POLICY RESULTS...".cyan());
    println!("    (This grabs the Resultant Set of Policy for the current user/computer)");

    let output = Command::new("gpresult")
        .arg("/r")
        .output()
        .expect("Failed to run gpresult");

    let result = String::from_utf8_lossy(&output.stdout).to_string();
    
    if result.len() < 10 {
        println!("{}", "    [!] Failed to get results (Are you running as Admin?)".red());
    } else {
        println!("{}", "    [+] GPO Data Captured.".green());
        logger::log_data("GPResult_Audit", &result);
        println!("    Saved to Lazarus_Reports folder.");
    }
    pause();
}

fn pause() {
    println!("\nPress Enter to continue...");
    let _ = std::io::stdin().read_line(&mut String::new());
}