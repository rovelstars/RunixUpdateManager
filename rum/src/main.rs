//! RunixUpdateManager (RUM) - the RunixOS on-device update client.
//!
//! - `check`   report device state, verify the manifest signature, print plan.   (P1)
//! - `apply`   reassemble an image from a chunk store into a file, verify hash.   (P2)
//! - `init`    bootstrap an A/B root (slot A = image, version), for testing.      (P3)
//! - `status`  show A/B boot-control state.                                       (P3)
//! - `stage`   reassemble the new image into the INACTIVE slot (seeded by the
//!             active slot), verify hash, and stage it for next boot.             (P3)
//! - `confirm` mark the currently-booted slot good (commit the update).           (P3)
//!
//! Slots are files under a root dir so the whole cycle is host-testable; on a
//! real device they are partitions and the boot-control area is protected.

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use runix_bootctl::{BootControl, Slot};
use runix_chunk::{ChunkIndex, Store, hash_hex, reassemble};
use runix_update_protocol::{CheckRequest, CheckResponse, Manifest, Version, SCHEMA};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "rum", about = "RunixOS update client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check the update server for a newer system release.
    Check {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server: String,
        #[arg(long, default_value = "keys/public.key")]
        key: PathBuf,
        #[arg(long, default_value = "x86_64")]
        arch: String,
        #[arg(long, default_value = "26.2.0")]
        current: String,
        #[arg(long, default_value = "stable")]
        channel: String,
        #[arg(long = "subscribe")]
        subscribed: Vec<String>,
    },
    /// Reassemble an image from a chunk store into a file (raw, no A/B).
    Apply {
        #[arg(long)]
        index: String,
        #[arg(long)]
        store: String,
        #[arg(long)]
        seed: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        expect: String,
    },
    /// Bootstrap an A/B root: slot A = image at the given version (first install).
    Init {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        version: String,
    },
    /// Show the A/B boot-control state.
    Status {
        #[arg(long)]
        root: PathBuf,
    },
    /// Stage an update into the inactive slot (seeded by the active slot).
    Stage {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        index: String,
        #[arg(long)]
        store: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        expect: String,
    },
    /// Mark the currently-booted slot good (commit the update).
    Confirm {
        #[arg(long)]
        root: PathBuf,
    },
}

// ---- slot layout ----

fn bootctl_path(root: &Path) -> PathBuf {
    root.join("bootctl.json")
}
fn slot_image(root: &Path, slot: Slot) -> PathBuf {
    root.join(format!("slot-{}", slot.as_str().to_lowercase())).join("core.img")
}

// ---- chunk store + reassembly (shared by apply + stage) ----

struct HttpStore {
    base: String,
}
impl Store for HttpStore {
    fn get(&self, hash: &str) -> Result<Vec<u8>, runix_chunk::Error> {
        let url = format!("{}/{}", self.base.trim_end_matches('/'), hash);
        let resp = ureq::get(&url)
            .call()
            .map_err(|_| runix_chunk::Error::NotFound(hash.to_string()))?;
        let mut buf = Vec::new();
        resp.into_reader().read_to_end(&mut buf)?;
        Ok(buf)
    }
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

fn load_index(spec: &str) -> Result<ChunkIndex> {
    let text = if is_url(spec) {
        ureq::get(spec).call().with_context(|| format!("GET {spec}"))?.into_string()?
    } else {
        std::fs::read_to_string(spec).with_context(|| format!("reading index {spec}"))?
    };
    serde_json::from_str(&text).context("parsing chunk index")
}

fn open_store(spec: &str) -> Box<dyn Store> {
    if is_url(spec) {
        Box::new(HttpStore { base: spec.to_string() })
    } else {
        Box::new(runix_chunk::LocalStore::new(spec))
    }
}

/// Reassemble + verify; returns the verified image bytes.
fn fetch_verified(index: &str, store: &str, seed: Option<&[u8]>, expect: &str) -> Result<Vec<u8>> {
    let index = load_index(index)?;
    let store = open_store(store);
    println!(
        "  {} chunks ({} unique), {} bytes, seed: {}",
        index.chunks.len(),
        index.unique(),
        index.total_len,
        if seed.is_some() { "yes" } else { "none" }
    );
    let (data, stats) = reassemble(&index, store.as_ref(), seed)
        .map_err(|e| anyhow!("reassembly failed: {e}"))?;
    let got = hash_hex(&data);
    if got != expect {
        bail!("image hash mismatch: got {got}, expected {expect} (refusing)");
    }
    println!(
        "  verified: reused {}, fetched {} ({} bytes)",
        stats.reused, stats.fetched, stats.bytes_fetched
    );
    Ok(data)
}

// ---- commands ----

fn check(
    server: &str,
    key_path: &Path,
    arch: String,
    current: &str,
    channel: String,
    subscribed: Vec<String>,
) -> Result<()> {
    let text = std::fs::read_to_string(key_path).with_context(|| format!("reading key {key_path:?}"))?;
    let public: [u8; 32] = hex::decode(text.trim())
        .context("public key not hex")?
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    let current: Version = current.parse().map_err(|_| anyhow!("bad --current version"))?;
    let req = CheckRequest { schema: SCHEMA, arch, current, channel, subscribed };

    let url = format!("{}/check", server.trim_end_matches('/'));
    let resp: CheckResponse = ureq::post(&url)
        .send_json(&req)
        .with_context(|| format!("POST {url}"))?
        .into_json()
        .context("decoding response")?;

    match resp {
        CheckResponse::UpToDate => println!("Up to date (system {current})."),
        CheckResponse::Update(signed) => {
            let m: Manifest = signed
                .verify(&public)
                .map_err(|e| anyhow!("signature verification failed: {e}"))?;
            println!("Update available: {} -> {}", current, m.version);
            println!("  signed by {} (verified), {}/{}", signed.key_id, m.channel, m.arch);
            println!("  image index {}  verity {}", m.image_index, m.verity_root_hash);
            println!(
                "\nNext: rum stage --root <root> --index {} --store <store> --version {} --expect {}",
                m.image_index, m.version, m.verity_root_hash
            );
        }
    }
    Ok(())
}

fn init(root: &Path, image: &Path, version: &str) -> Result<()> {
    let version: Version = version.parse().map_err(|_| anyhow!("bad --version"))?;
    let dst = slot_image(root, Slot::A);
    std::fs::create_dir_all(dst.parent().unwrap())?;
    std::fs::create_dir_all(slot_image(root, Slot::B).parent().unwrap())?;
    std::fs::copy(image, &dst).with_context(|| format!("copying image to {dst:?}"))?;
    let bc = BootControl::initial(version);
    bc.save(&bootctl_path(root))?;
    println!("Initialized A/B root at {root:?}: slot A = {version} (good, current)");
    Ok(())
}

fn print_status(root: &Path) -> Result<()> {
    let bc = BootControl::load(&bootctl_path(root))?;
    for s in [Slot::A, Slot::B] {
        let m = bc.meta(s);
        let ver = m.version.map(|v| v.to_string()).unwrap_or_else(|| "empty".into());
        let state = if !m.bootable() {
            "unbootable"
        } else if m.successful {
            "good"
        } else {
            "trial"
        };
        println!(
            "slot {} [{}] prio={} tries={} {}{}",
            s.as_str(),
            ver,
            m.priority,
            m.tries,
            state,
            if bc.current == s { "  <- current" } else { "" }
        );
    }
    println!("inactive (update target): slot {}", bc.inactive().as_str());
    Ok(())
}

fn stage(root: &Path, index: &str, store: &str, version: &str, expect: &str) -> Result<()> {
    let version: Version = version.parse().map_err(|_| anyhow!("bad --version"))?;
    let mut bc = BootControl::load(&bootctl_path(root))?;
    let target = bc.inactive();
    let active_img = slot_image(root, bc.current);
    let seed = std::fs::read(&active_img).ok();
    if seed.is_some() {
        println!("Staging into slot {} (seeded by active slot {})", target.as_str(), bc.current.as_str());
    } else {
        println!("Staging into slot {} (no seed)", target.as_str());
    }

    let data = fetch_verified(index, store, seed.as_deref(), expect)?;
    let dst = slot_image(root, target);
    std::fs::create_dir_all(dst.parent().unwrap())?;
    std::fs::write(&dst, &data).with_context(|| format!("writing slot {dst:?}"))?;

    bc.stage(target, version);
    bc.save(&bootctl_path(root))?;
    println!(
        "Staged {} to slot {} (trial). Reboot to try it; `rum confirm` after a good boot.",
        version,
        target.as_str()
    );
    Ok(())
}

fn confirm(root: &Path) -> Result<()> {
    let mut bc = BootControl::load(&bootctl_path(root))?;
    bc.mark_successful();
    bc.save(&bootctl_path(root))?;
    println!("Confirmed slot {} good (update committed).", bc.current.as_str());
    Ok(())
}

fn apply(index: &str, store: &str, seed: Option<PathBuf>, out: &Path, expect: &str) -> Result<()> {
    let seed_data = match &seed {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("reading seed {p:?}"))?),
        None => None,
    };
    println!("Applying image -> {out:?}");
    let data = fetch_verified(index, store, seed_data.as_deref(), expect)?;
    std::fs::write(out, &data).with_context(|| format!("writing {out:?}"))?;
    println!("Wrote {out:?} (hash OK).");
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Check { server, key, arch, current, channel, subscribed } => {
            check(&server, &key, arch, &current, channel, subscribed)
        }
        Command::Apply { index, store, seed, out, expect } => apply(&index, &store, seed, &out, &expect),
        Command::Init { root, image, version } => init(&root, &image, &version),
        Command::Status { root } => print_status(&root),
        Command::Stage { root, index, store, version, expect } => {
            stage(&root, &index, &store, &version, &expect)
        }
        Command::Confirm { root } => confirm(&root),
    }
}
