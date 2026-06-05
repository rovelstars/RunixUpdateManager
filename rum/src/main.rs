//! RunixUpdateManager (RUM) - the RunixOS on-device update client.
//!
//! MVP: the `check` command reports this device's state to RunixUpdateServer,
//! verifies the returned manifest against the RovelStars public key, and prints
//! the update plan. Later phases add chunk sync (fetch only missing chunks into
//! the inactive A/B slot), verity verification, and the A/B switch.

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use runix_update_protocol::{CheckRequest, CheckResponse, Manifest, Version, SCHEMA};
use std::path::PathBuf;

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
        /// Update server base URL.
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server: String,
        /// Path to the RovelStars public key (hex, 32 bytes). On a real system
        /// this lives in the verity-protected /Core.
        #[arg(long, default_value = "keys/public.key")]
        key: PathBuf,
        /// Device architecture.
        #[arg(long, default_value = "x86_64")]
        arch: String,
        /// Currently installed system version (e.g. 26.2.0).
        #[arg(long, default_value = "26.2.0")]
        current: String,
        /// Base system channel.
        #[arg(long, default_value = "stable")]
        channel: String,
        /// Subscribed vendor/optional channels (repeatable).
        #[arg(long = "subscribe")]
        subscribed: Vec<String>,
    },
}

fn load_public_key(path: &PathBuf) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading public key {path:?}"))?;
    let bytes = hex::decode(text.trim()).context("public key is not valid hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))
}

fn check(
    server: &str,
    key_path: &PathBuf,
    arch: String,
    current: &str,
    channel: String,
    subscribed: Vec<String>,
) -> Result<()> {
    let public = load_public_key(key_path)?;
    let current: Version = current.parse().map_err(|_| anyhow!("bad --current version"))?;

    let req = CheckRequest {
        schema: SCHEMA,
        arch,
        current,
        channel,
        subscribed,
    };

    let url = format!("{}/check", server.trim_end_matches('/'));
    let resp: CheckResponse = ureq::post(&url)
        .send_json(&req)
        .with_context(|| format!("POST {url}"))?
        .into_json()
        .context("decoding server response")?;

    match resp {
        CheckResponse::UpToDate => {
            println!("Up to date (system {current}).");
        }
        CheckResponse::Update(signed) => {
            // The signature is the trust boundary: an intercepted/forged
            // manifest fails here, before we ever act on it.
            let manifest: Manifest = signed
                .verify(&public)
                .map_err(|e| anyhow!("manifest signature verification failed: {e}"))?;
            print_plan(&current, &signed.key_id, &manifest)?;
        }
    }
    Ok(())
}

fn print_plan(current: &Version, key_id: &str, m: &Manifest) -> Result<()> {
    if m.version <= *current {
        bail!("server offered version {} which is not newer than {current}", m.version);
    }
    if *current < m.min_source {
        println!(
            "Update {} -> {} available, but this version is too old for a delta \
             (min source {}); a full image is required.",
            current, m.version, m.min_source
        );
    } else {
        println!("Update available: {} -> {}", current, m.version);
    }
    println!("  signed by:   {key_id} (signature verified)");
    println!("  channel:     {} / {}", m.channel, m.arch);
    println!("  image index: {}", m.image_index);
    println!("  verity hash: {}", m.verity_root_hash);
    println!("  size:        {} bytes", m.size);
    if m.packages.is_empty() {
        println!("  packages:    none");
    } else {
        println!("  packages:");
        for p in &m.packages {
            println!("    - {} {} ({})", p.name, p.version, p.channel);
        }
    }
    println!("\n(Phase 1: check + verify only. Chunk fetch + A/B apply come next.)");
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Check {
            server,
            key,
            arch,
            current,
            channel,
            subscribed,
        } => check(&server, &key, arch, &current, channel, subscribed),
    }
}
