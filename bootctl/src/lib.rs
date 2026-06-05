//! A/B boot-control for RunixOS - shared by RUM (writes updates, std) and
//! Rignite (selects the slot to boot, no_std UEFI). Same scheme Android/ChromeOS
//! use: per-slot priority + a trial-boot try counter + a "successful" flag.
//!
//! An update is staged into the inactive slot at higher priority with N tries
//! and successful=false. The bootloader boots the highest-priority bootable
//! slot; each trial boot burns a try; if the tries run out before the slot is
//! confirmed good, it becomes unbootable and the bootloader falls back to the
//! previous good slot (automatic rollback).
//!
//! This crate is `no_std` with no dependencies and a fixed 64-byte binary
//! on-disk format (`to_bytes`/`from_bytes`), so Rignite and RUM read/write the
//! exact same boot-control block. I/O is left to the caller.

#![cfg_attr(not(test), no_std)]

use core::fmt;

/// Trial boots allowed for a freshly staged slot before rollback.
pub const DEFAULT_TRIES: u8 = 3;

/// Fixed size of the serialized boot-control block.
pub const BLOCK_SIZE: usize = 64;

const MAGIC: [u8; 4] = *b"RBCT";
const FORMAT_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, Default)]
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

#[derive(Clone, Copy, Debug)]
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

    /// Stage an update written to `target`: highest-priority trial slot.
    pub fn stage(&mut self, target: Slot, version: Version) {
        let rollback_prio = self.meta(target.other()).priority.max(1);
        let m = self.meta_mut(target);
        m.version = Some(version);
        m.priority = rollback_prio + 1;
        m.tries = DEFAULT_TRIES;
        m.successful = false;
    }

    /// Bootloader: pick the slot to boot = highest-priority bootable slot
    /// (preferring current on a tie). None means nothing is bootable.
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

    /// Bootloader: account for booting `slot` (call once per boot, after select).
    /// Burns a trial try; when exhausted unconfirmed, the slot becomes
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

    // ---- fixed 64-byte binary format (no_std, no serde) ----
    // [0..4] magic "RBCT" | [4] format ver | [5] current (0=A,1=B)
    // [6..22] slot A meta | [22..38] slot B meta | [38..64] reserved (0)
    // slot meta (16B): major u32, minor u32, patch u32 (LE), priority, tries,
    //                  successful (0/1), has_version (0/1)

    pub fn to_bytes(&self) -> [u8; BLOCK_SIZE] {
        let mut b = [0u8; BLOCK_SIZE];
        b[0..4].copy_from_slice(&MAGIC);
        b[4] = FORMAT_VERSION;
        b[5] = match self.current {
            Slot::A => 0,
            Slot::B => 1,
        };
        write_slot(&mut b[6..22], &self.a);
        write_slot(&mut b[22..38], &self.b);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 38 || b[0..4] != MAGIC || b[4] != FORMAT_VERSION {
            return None;
        }
        let current = match b[5] {
            0 => Slot::A,
            1 => Slot::B,
            _ => return None,
        };
        Some(BootControl {
            current,
            a: read_slot(&b[6..22]),
            b: read_slot(&b[22..38]),
        })
    }
}

fn write_slot(out: &mut [u8], m: &SlotMeta) {
    let v = m.version.unwrap_or(Version::new(0, 0, 0));
    out[0..4].copy_from_slice(&v.major.to_le_bytes());
    out[4..8].copy_from_slice(&v.minor.to_le_bytes());
    out[8..12].copy_from_slice(&v.patch.to_le_bytes());
    out[12] = m.priority;
    out[13] = m.tries;
    out[14] = m.successful as u8;
    out[15] = m.version.is_some() as u8;
}

fn read_slot(b: &[u8]) -> SlotMeta {
    let u32le = |s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
    let version = if b[15] != 0 {
        Some(Version::new(u32le(&b[0..4]), u32le(&b[4..8]), u32le(&b[8..12])))
    } else {
        None
    };
    SlotMeta { version, priority: b[12], tries: b[13], successful: b[14] != 0 }
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
        assert_eq!(bc.inactive(), Slot::B);
        bc.stage(Slot::B, v(3));
        assert_eq!(bc.select(), Some(Slot::B));
        bc.begin_boot(Slot::B);
        assert_eq!(bc.b.tries, DEFAULT_TRIES - 1);
        bc.mark_successful();
        assert!(bc.b.successful);
        assert_eq!(bc.select(), Some(Slot::B));
    }

    #[test]
    fn rollback_when_trial_never_confirmed() {
        let mut bc = BootControl::initial(v(2));
        bc.stage(Slot::B, v(3));
        for _ in 0..DEFAULT_TRIES {
            let s = bc.select().unwrap();
            bc.begin_boot(s);
        }
        assert_eq!(bc.select(), Some(Slot::A));
        assert!(!bc.b.bootable());
    }

    #[test]
    fn confirm_within_tries_keeps_new_slot() {
        let mut bc = BootControl::initial(v(2));
        bc.stage(Slot::B, v(3));
        let s = bc.select().unwrap();
        bc.begin_boot(s);
        bc.mark_successful();
        for _ in 0..5 {
            let s = bc.select().unwrap();
            bc.begin_boot(s);
        }
        assert_eq!(bc.select(), Some(Slot::B));
    }

    #[test]
    fn binary_roundtrip() {
        let mut bc = BootControl::initial(v(2));
        bc.stage(Slot::B, v(3));
        bc.begin_boot(Slot::B);
        let bytes = bc.to_bytes();
        let back = BootControl::from_bytes(&bytes).unwrap();
        assert_eq!(back.current, Slot::B);
        assert_eq!(back.a.version, Some(v(2)));
        assert_eq!(back.b.version, Some(v(3)));
        assert_eq!(back.b.tries, DEFAULT_TRIES - 1);
        assert!(back.a.successful);
        assert!(!back.b.successful);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(BootControl::from_bytes(&[0u8; BLOCK_SIZE]).is_none());
    }
}
