use crate::{net, system, forensics, sharepoint, domain}; // Added domain
use colored::*;
use dialoguer::{Select, MultiSelect, theme::ColorfulTheme};
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

const FAVORITES_FILE: &str = "lazarus_favorites.json";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct FavoriteTool {
    id: String,
    name: String,
}

// REGISTER ALL TOOLS HERE
fn get_all_tools() -> Vec<(&'static str, &'static str)> {
    vec![
        // Network
        ("net_scan", "Subnet Fingerprinter"),
        ("net_wifi", "Wi-Fi Operations"),
        ("net_nuke", "Network Nuke"),
        ("net_ping", "Connectivity Test"),
        // System
        ("sys_backup", "User Profile Backup"),
        ("sys_restore", "User Profile Restore"),
        ("sys_fslogix", "FSLogix Medic"),
        ("sys_bloat", "Remove Bloatware"),
        ("sys_browser", "Browser Deep Clean"),
        ("sys_updates", "Nuke Windows Updates"),
        ("sys_spooler", "Fix Print Spooler"),
        ("sys_sfc", "Full System Repair"),
        ("sys_rogue", "Rogue Admin Hunter"),
        ("sys_lock", "File Locksmith"),
        ("sys_dupe", "Duplicate File Destroyer"),
        ("sys_uwp", "UWP App Surgeon"),
        ("sys_drivers", "Driver Teleporter"),
        ("sys_reboot", "Fix Stuck Reboot Loop"),
        ("sys_unblock", "Bulk File Unblocker"),
        ("sys_trust", "Trust Server Zone"),
        ("sys_service", "Hung Service Assassin"),
        // Domain (THESE WERE MISSING)
        ("dom_trust", "Analyze Domain Trust"),
        ("dom_repair", "Repair Domain Trust"),
        ("dom_gpu", "Force GPUpdate"),
        ("dom_audit", "Audit Applied GPO"),
        ("dom_sync", "Force Azure AD Sync"),
        ("dom_lock", "Find Locked Users"),
        // Forensics
        ("for_bsod", "BSOD Analyzer Pro"),
        ("for_usb", "USB History Viewer"),
        ("for_pii", "PII Hunter"),
        ("for_acl", "ACL Sentinel"),
        // SharePoint
        ("sp_nuke", "OneDrive Nuclear Reset"),
        ("sp_scan", "SharePoint Pre-Flight"),
    ]
}

// EXECUTE TOOL
fn run_tool_by_id(id: &str) {
    match id {
        "net_scan" => net::subnet_fingerprinter(),
        "net_wifi" => net::wifi_menu(),
        "net_nuke" => net::network_nuke(),
        "net_ping" => net::connectivity_test(),
        "sys_backup" => system::profile_backup_workflow(),
        "sys_restore" => system::profile_restore_workflow(),
        "sys_fslogix" => system::fslogix_medic(),
        "sys_bloat" => system::remove_bloatware(),
        "sys_browser" => system::browser_deep_clean(),
        "sys_updates" => system::nuke_windows_updates(),
        "sys_spooler" => system::print_spooler_cpr(),
        "sys_sfc" => system::run_sfc(),
        "sys_rogue" => system::rogue_admin_hunter(),
        "sys_lock" => system::file_locksmith(),
        "sys_dupe" => system::duplicate_file_destroyer(),
        "sys_uwp" => system::uwp_app_surgeon(),
        "sys_drivers" => system::driver_teleporter(),
        "sys_reboot" => system::nuke_pending_reboot(),
        "sys_unblock" => system::bulk_unblocker(),
        "sys_trust" => system::trust_server_zone(),
        "sys_service" => system::hung_service_assassin(),
        // Domain Tools
        "dom_trust" => domain::check_trust(),
        "dom_repair" => domain::repair_trust(),
        "dom_gpu" => domain::force_gpupdate(),
        "dom_audit" => domain::audit_gpo(),
        "dom_sync" => domain::force_adsync(),
        "dom_lock" => domain::list_locked_users(),
        // Forensics
        "for_bsod" => forensics::bsod_analyzer(),
        "for_usb" => forensics::usb_history_viewer(),
        "for_pii" => forensics::pii_hunter(),
        "for_acl" => forensics::acl_sentinel(),
        // SharePoint
        "sp_nuke" => sharepoint::onedrive_nuclear_reset(),
        "sp_scan" => sharepoint::preflight_scan(),
        _ => println!("{}", "Tool not linked yet.".red()),
    }
}

pub fn menu() {
    loop {
        let mut favorites = load_favorites();
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", "--- ⭐ QUICK ACCESS FAVORITES ---".yellow().bold());

        let mut choices: Vec<String> = favorites.iter().map(|f| format!("Run: {}", f.name)).collect();
        choices.push("-------------------------".dimmed().to_string());
        choices.push("(+) Add New Favorite".green().to_string());
        choices.push("(-) Remove Favorite".red().to_string());
        choices.push("Back".to_string());

        let selection = Select::with_theme(&ColorfulTheme::default()).with_prompt("Select Tool").default(0).items(&choices).interact().unwrap();

        if selection < favorites.len() {
            run_tool_by_id(&favorites[selection].id);
        } else {
            let action = &choices[selection];
            if action.contains("(+) Add") { add_favorite_workflow(&mut favorites); }
            else if action.contains("(-) Remove") { remove_favorite_workflow(&mut favorites); }
            else if action == "Back" { break; }
        }
    }
}

fn add_favorite_workflow(current_favs: &mut Vec<FavoriteTool>) {
    let all = get_all_tools();
    let available: Vec<_> = all.iter().filter(|(id, _)| !current_favs.iter().any(|f| f.id == *id)).collect();
    if available.is_empty() { println!("{}", "All tools added!".green()); wait(); return; }
    
    let choices: Vec<&str> = available.iter().map(|(_, name)| *name).collect();
    let sels = MultiSelect::with_theme(&ColorfulTheme::default()).with_prompt("Select tools to ADD").items(&choices).interact().unwrap();
    
    if !sels.is_empty() {
        for idx in sels {
            let (id, name) = available[idx];
            current_favs.push(FavoriteTool { id: id.to_string(), name: name.to_string() });
        }
        save_favorites(current_favs);
        println!("{}", "Updated.".green());
    }
}

fn remove_favorite_workflow(current_favs: &mut Vec<FavoriteTool>) {
    if current_favs.is_empty() { return; }
    let choices: Vec<String> = current_favs.iter().map(|f| f.name.clone()).collect();
    let sels = MultiSelect::with_theme(&ColorfulTheme::default()).with_prompt("Select tools to REMOVE").items(&choices).interact().unwrap();
    
    if !sels.is_empty() {
        let mut indices = sels;
        indices.sort_by(|a, b| b.cmp(a));
        for i in indices { current_favs.remove(i); }
        save_favorites(current_favs);
        println!("{}", "Updated.".green());
    }
}

fn load_favorites() -> Vec<FavoriteTool> {
    if Path::new(FAVORITES_FILE).exists() {
        if let Ok(data) = fs::read_to_string(FAVORITES_FILE) {
            if let Ok(favs) = serde_json::from_str(&data) { return favs; }
        }
    }
    Vec::new()
}

fn save_favorites(favs: &Vec<FavoriteTool>) {
    if let Ok(data) = serde_json::to_string_pretty(favs) { let _ = fs::write(FAVORITES_FILE, data); }
}

fn wait() { println!("\nPress Enter..."); let _ = std::io::stdin().read_line(&mut String::new()); }