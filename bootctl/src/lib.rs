//! A/B boot-control for RunixOS - shared by RUM (writes updates) and Rignite
//! (selects the slot to boot). Models the same scheme Android/ChromeOS use:
//! per-slot priority + a trial-boot try counter + a "successful" flag.
//!
//! An update is staged into the inactive slot at higher priority with N tries
//! and successful=false. The bootloader boots the highest-priority bootable
//! slot; each trial boot burns a try; if the tries run out before the slot is
//! confirmed good, it becomes unbootable and the bootloader falls back to the
//! previous good slot (automatic rollback).
//!
//! On a real device this state lives in a protected boot-control area (GPT attrs
//! / a small partition). Here it is a JSON file so the whole cycle is testable.

use runix_update_protocol::Version;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const DEFAULT_TRIES: u8 = 3;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Slot::A => "A",
            Slot::B => "B",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SlotMeta {
    pub version: Option<Version>,
    /// Higher wins. 0 = unbootable.
    pub priority: u8,
    /// Remaining trial-boot attempts.
    pub tries: u8,
    /// Confirmed-good (post-boot). Once true, tries no longer matter.
    pub successful: bool,
}

impl SlotMeta {
    pub fn bootable(&self) -> bool {
        self.priority > 0 && (self.successful || self.tries > 0)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BootControl {
    /// The slot currently running (set by the bootloader at boot).
    pub current: Slot,
    pub a: SlotMeta,
    pub b: SlotMeta,
}

impl BootControl {
    /// First install: slot A holds `version`, good and current; B empty.
    pub fn initial(version: Version) -> Self {
        BootControl {
            current: Slot::A,
            a: SlotMeta { version: Some(version), priority: 1, tries: 0, successful: true },
            b: SlotMeta::default(),
        }
    }

    pub fn meta(&self, s: Slot) -> &SlotMeta {
        match s {
            Slot::A => &self.a,
            Slot::B => &self.b,
        }
    }
    pub fn meta_mut(&mut self, s: Slot) -> &mut SlotMeta {
        match s {
            Slot::A => &mut self.a,
            Slot::B => &mut self.b,
        }
    }

    /// The slot an update should be written to (the one not running).
    pub fn inactive(&self) -> Slot {
        self.current.other()
    }

    /// Stage an update that was written to `target`: make it the highest-priority
    /// trial slot. The other slot keeps its priority as the rollback target.
    pub fn stage(&mut self, target: Slot, version: Version) {
        let rollback_prio = self.meta(target.other()).priority.max(1);
        let m = self.meta_mut(target);
        m.version = Some(version);
        m.priority = rollback_prio + 1;
        m.tries = DEFAULT_TRIES;
        m.successful = false;
    }

    /// Bootloader: pick the slot to boot = highest-priority bootable slot
    /// (preferring the current slot on a tie). None means nothing is bootable.
    pub fn select(&self) -> Option<Slot> {
        let mut best: Option<Slot> = None;
        for s in [Slot::A, Slot::B] {
            if !self.meta(s).bootable() {
                continue;
            }
            best = match best {
                None => Some(s),
                Some(b) => {
                    let (ps, pb) = (self.meta(s).priority, self.meta(b).priority);
                    if ps > pb || (ps == pb && s == self.current) {
                        Some(s)
                    } else {
                        Some(b)
                    }
                }
            };
        }
        best
    }

    /// Bootloader: account for booting `slot`. Call once per boot, after select.
    /// Burns a trial try; if the tries run out unconfirmed, the slot becomes
    /// unbootable so the next select falls back (rollback).
    pub fn begin_boot(&mut self, slot: Slot) {
        self.current = slot;
        let m = self.meta_mut(slot);
        if !m.successful && m.tries > 0 {
            m.tries -= 1;
            if m.tries == 0 {
                m.priority = 0;
            }
        }
    }

    /// Post-boot: confirm the current slot is good (commits the update).
    pub fn mark_successful(&mut self) {
        let cur = self.current;
        let m = self.meta_mut(cur);
        m.successful = true;
        if m.priority == 0 {
            m.priority = 1;
        }
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(p: u32) -> Version {
        Version::new(26, p, 0)
    }

    #[test]
    fn happy_path_stage_boot_confirm() {
        let mut bc = BootControl::initial(v(2));
        assert_eq!(bc.current, Slot::A);
        assert_eq!(bc.inactive(), Slot::B);

        bc.stage(Slot::B, v(3));
        assert_eq!(bc.select(), Some(Slot::B)); // higher priority

        bc.begin_boot(Slot::B);
        assert_eq!(bc.current, Slot::B);
        assert_eq!(bc.b.tries, DEFAULT_TRIES - 1);
        assert!(!bc.b.successful);

        bc.mark_successful();
        assert!(bc.b.successful);
        assert_eq!(bc.select(), Some(Slot::B)); // B committed
    }

    #[test]
    fn rollback_when_trial_never_confirmed() {
        let mut bc = BootControl::initial(v(2));
        bc.stage(Slot::B, v(3));
        // Boot B repeatedly without ever confirming (crash loop).
        for _ in 0..DEFAULT_TRIES {
            let s = bc.select().unwrap();
            bc.begin_boot(s);
        }
        // B exhausted its tries -> unbootable -> next select falls back to A.
        assert_eq!(bc.select(), Some(Slot::A));
        assert!(!bc.b.bootable());
    }

    #[test]
    fn confirm_within_tries_keeps_new_slot() {
        let mut bc = BootControl::initial(v(2));
        bc.stage(Slot::B, v(3));
        let s = bc.select().unwrap();
        bc.begin_boot(s); // 1 try used
        bc.mark_successful(); // confirmed before exhaustion
        // Even after many reboots, B stays selected (successful).
        for _ in 0..5 {
            let s = bc.select().unwrap();
            bc.begin_boot(s);
        }
        assert_eq!(bc.select(), Some(Slot::B));
    }
}
