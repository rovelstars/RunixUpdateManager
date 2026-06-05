//! rignite-sim - simulates the Rignite bootloader's slot selection so the
//! trial-boot / rollback cycle is testable without rebooting real hardware. It
//! reads/writes the same fixed binary boot-control block real Rignite uses.
//!
//! Usage:
//!   rignite-sim <root> status   show the boot-control state
//!   rignite-sim <root> boot     pick the bootable slot, account for a trial boot

use runix_bootctl::{BootControl, Slot};
use std::path::PathBuf;

fn load(path: &std::path::Path) -> BootControl {
    let bytes = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("rignite-sim: cannot read {path:?}: {e}");
        std::process::exit(1);
    });
    BootControl::from_bytes(&bytes).unwrap_or_else(|| {
        eprintln!("rignite-sim: invalid boot-control block at {path:?}");
        std::process::exit(1);
    })
}

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
    let path = PathBuf::from(&args[1]).join("bootctl.bin");
    let mut bc = load(&path);

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
                if let Err(e) = std::fs::write(&path, bc.to_bytes()) {
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
