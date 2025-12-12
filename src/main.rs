use colored::*;
use dialoguer::{Select, theme::ColorfulTheme};

mod net;
mod system;
mod forensics;
mod logger;
mod domain;
mod sharepoint;
mod update;

const VERSION: &str = "3.0.0"; 

fn main() {
    loop {
        print!("\x1B[2J\x1B[1;1H");

        println!("{}", "=========================================".green().bold());
        println!("       LAZARUS RECOVERY TOOL v{}        ", VERSION.green().bold());
        println!("{}", "     Offline Repair & Forensics Unit     ".green());
        println!("{}", "=========================================".green().bold());
        println!();

        let choices = &[
            "1. Network Tools (Reset, WiFi, Ping Test)",
            "2. System Repair (Updates, Sage, FSLogix)",
            "3. Domain & Identity (Trust, GPO)",
            "4. Forensics (USB, Startup, Logs)",
            "5. SharePoint Pre-Flight Scan",
            "6. Check for Updates", 
            "Exit",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select Action")
            .default(0)
            .items(&choices[..])
            .interact()
            .unwrap();

        match selection {
            0 => net::menu(),
            1 => system::menu(),
            2 => domain::menu(),
            3 => forensics::menu(),
            4 => sharepoint::menu(),
            5 => update::check_for_updates(VERSION),
            _ => {
                println!("{}", "Exiting Lazarus...".red());
                break;
            }
        }
    }
}