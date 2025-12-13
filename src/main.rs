use colored::*;
use dialoguer::{Select, theme::ColorfulTheme};

mod net;
mod system;
mod forensics;
mod logger;
mod domain;
mod sharepoint;
mod update;
mod favorites; // <--- NEW MODULE

const VERSION: &str = "3.0.6"; 

fn main() {
    let _ = enable_ansi_support::enable_ansi_support();

    loop {
        print!("\x1B[2J\x1B[1;1H");

        println!("{}", "=========================================".green().bold());
        println!("       LAZARUS RECOVERY TOOL v{}        ", VERSION.green().bold());
        println!("{}", "     Offline Repair & Forensics Unit     ".green());
        println!("{}", "=========================================".green().bold());
        println!();

        let choices = &[
            "0. ⭐ Favorites (Quick Access)", // <--- NEW OPTION
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
            0 => favorites::menu(),
            1 => net::menu(),
            2 => system::menu(),
            3 => domain::menu(),
            4 => forensics::menu(),
            5 => sharepoint::menu(),
            6 => update::check_for_updates(VERSION),
            _ => {
                println!("{}", "Exiting Lazarus...".red());
                break;
            }
        }
    }
}