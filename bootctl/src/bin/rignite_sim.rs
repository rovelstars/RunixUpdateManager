//! rignite-sim - simulates the Rignite bootloader's slot selection, so the
//! trial-boot / rollback cycle is testable without rebooting real hardware.
//!
//! Usage:
//!   rignite-sim <root> status   show the boot-control state
//!   rignite-sim <root> boot     pick the bootable slot, account for a trial boot
//!
//! Run `boot` repeatedly without `rum confirm` to watch a bad update roll back.

use runix_bootctl::{BootControl, Slot};
use std::path::PathBuf;

fn describe(bc: &BootControl, s: Slot) -> String {
    let m = bc.meta(s);
    let ver = m.version.map(|v| v.to_string()).unwrap_or_else(|| "empty".into());
    let state = if !m.bootable() {
        "unbootable".to_string()
    } else if m.successful {
        "good".to_string()
    } else {
        format!("trial, {} tries left", m.tries)
    };
    format!(
        "slot {} [{}] prio={} {}{}",
        s.as_str(),
        ver,
        m.priority,
        state,
        if bc.current == s { " (current)" } else { "" }
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rignite-sim <root> <boot|status>");
        std::process::exit(2);
    }
    let root = PathBuf::from(&args[1]);
    let state_path = root.join("bootctl.json");

    let mut bc = match BootControl::load(&state_path) {
        Ok(bc) => bc,
        Err(e) => {
            eprintln!("rignite-sim: cannot load {state_path:?}: {e}");
            std::process::exit(1);
        }
    };

    match args[2].as_str() {
        "status" => {
            println!("{}", describe(&bc, Slot::A));
            println!("{}", describe(&bc, Slot::B));
        }
        "boot" => match bc.select() {
            None => {
                eprintln!("RIGNITE: no bootable slot - system is unbootable!");
                std::process::exit(1);
            }
            Some(s) => {
                bc.begin_boot(s);
                if let Err(e) = bc.save(&state_path) {
                    eprintln!("rignite-sim: save failed: {e}");
                    std::process::exit(1);
                }
                println!("RIGNITE: {}", describe(&bc, s));
            }
        },
        other => {
            eprintln!("rignite-sim: unknown command {other:?}");
            std::process::exit(2);
        }
    }
}
